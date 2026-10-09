package rbac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The gateway view: what the gateway decides every request from, kept in Redis (internal/redisview)
// and read there from a replica. Postgres is the truth; each write updates the keys it changed
// after its commit, and Rebuild rewrites everything at boot.

// Route values besides a permission key, and the permission a grants_all role holds.
const (
	RoutePublic   = "public"
	AllPermission = "*"
)

// View is the gateway view's store. Every Put replaces its key whole.
type View interface {
	PutRoutes(ctx context.Context, routes map[string]string) error
	PutConsumer(ctx context.Context, permissions []string) error
	PutCompany(ctx context.Context, companyID, status string) error
	PutRole(ctx context.Context, r RoleView) error
	DeleteRole(ctx context.Context, companyID, roleID string) error
	PutUserVersion(ctx context.Context, sub string, version int64) error
	DeleteUser(ctx context.Context, sub string) error
	// Replace writes the whole view and deletes every key it does not list.
	Replace(ctx context.Context, s Snapshot) error
}

// Snapshot is the whole gateway view.
type Snapshot struct {
	Routes    map[string]string // route name -> permission key, or RoutePublic
	Consumer  []string
	Companies map[string]string // company id -> status
	Roles     []RoleView
	Users     map[string]int64 // sub -> authorization version
}

// RoleView is a role's live permissions; a grants_all role holds AllPermission only.
type RoleView struct {
	CompanyID, RoleID string
	Permissions       []string
}

// viewLock serialises Rebuild against writes: writes hold it shared from their transaction until
// their view update is done, Rebuild holds it exclusively, so a rebuild never overwrites a
// concurrent write's update with an older snapshot.
const viewLock = `hashtext('authz.view')`

// viewTimeout bounds a view update: past it the write is logged and left to the next rebuild.
const viewTimeout = 5 * time.Second

// write runs fn in a transaction and, once it has committed, project to update the gateway view.
// A failed view update is logged, not returned: the write is committed, and the next boot's
// Rebuild repairs the view.
func (s *Service) write(ctx context.Context, fn func(pgx.Tx) error, project func(context.Context) error) error {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer releaseLocked(conn, `SELECT pg_advisory_unlock_shared(`+viewLock+`)`)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock_shared(`+viewLock+`)`); err != nil {
		return err
	}
	if err := pgx.BeginFunc(ctx, conn, fn); err != nil {
		return err
	}
	if project == nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), viewTimeout)
	defer cancel()
	if err := project(pctx); err != nil {
		slog.Error("gateway view not updated; the next boot rebuilds it", "err", err)
	}
	return nil
}

// releaseLocked runs unlock and returns the connection to the pool, or closes it if the unlock
// failed: a session lock must never stay on a pooled connection.
func releaseLocked(conn *pgxpool.Conn, unlock string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, unlock); err != nil {
		_ = conn.Conn().Close(ctx)
	}
	conn.Release()
}

// Rebuild rewrites the whole gateway view from Postgres (at boot: it repairs a missed update and
// fills an empty Redis).
func (s *Service) Rebuild(ctx context.Context) error {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer releaseLocked(conn, `SELECT pg_advisory_unlock(`+viewLock+`)`)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(`+viewLock+`)`); err != nil {
		return err
	}
	var snap Snapshot
	err = pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if snap.Routes, err = routesView(ctx, tx); err != nil {
			return err
		}
		if snap.Consumer, err = consumerView(ctx, tx); err != nil {
			return err
		}
		if snap.Roles, err = rolesView(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text, status FROM companies`)
		if err != nil {
			return err
		}
		snap.Companies = map[string]string{}
		var id, status string
		if _, err := pgx.ForEachRow(rows, []any{&id, &status}, func() error { snap.Companies[id] = status; return nil }); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT sub, authz_version FROM members`)
		if err != nil {
			return err
		}
		snap.Users = map[string]int64{}
		var sub string
		var version int64
		_, err = pgx.ForEachRow(rows, []any{&sub, &version}, func() error { snap.Users[sub] = version; return nil })
		return err
	})
	if err != nil {
		return err
	}
	if err := s.View.Replace(ctx, snap); err != nil {
		return fmt.Errorf("gateway view: %w", err)
	}
	return nil
}

// routesView is every live route. A route whose permission is deprecated is left out, so it is
// denied.
func routesView(ctx context.Context, q querier) (map[string]string, error) {
	rows, err := q.Query(ctx, `
		SELECT r.name, coalesce(r.permission_key, $1) FROM routes r
		LEFT JOIN permissions p ON p.key = r.permission_key
		WHERE r.deprecated_at IS NULL AND (r.public OR p.deprecated_at IS NULL)`, RoutePublic)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var name, value string
	_, err = pgx.ForEachRow(rows, []any{&name, &value}, func() error { out[name] = value; return nil })
	return out, err
}

func consumerView(ctx context.Context, q querier) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT key FROM permissions WHERE consumer AND deprecated_at IS NULL ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// rolesView is the live permissions of the given roles, or of every role when ids is empty.
func rolesView(ctx context.Context, q querier, ids ...string) ([]RoleView, error) {
	rows, err := q.Query(ctx, `
		SELECT r.company_id::text, r.id::text,
		       CASE WHEN r.grants_all THEN ARRAY[$1]
		            ELSE coalesce(array_agg(rp.permission_key ORDER BY rp.permission_key)
		                          FILTER (WHERE rp.permission_key IS NOT NULL AND p.deprecated_at IS NULL), '{}') END
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.key = rp.permission_key
		WHERE coalesce(cardinality($2::text[]), 0) = 0 OR r.id::text = ANY($2)
		GROUP BY r.id`, AllPermission, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RoleView])
}

// putRole updates one role in the view, deleting it if it no longer exists.
func (s *Service) putRole(ctx context.Context, companyID, roleID string) error {
	roles, err := rolesView(ctx, s.DB, roleID)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return s.View.DeleteRole(ctx, companyID, roleID)
	}
	return s.View.PutRole(ctx, roles[0])
}

// putCatalogue updates the routes, the consumer set and every role: a deprecated permission
// leaves every role that holds it.
func (s *Service) putCatalogue(ctx context.Context) error {
	routes, err := routesView(ctx, s.DB)
	if err != nil {
		return err
	}
	consumer, err := consumerView(ctx, s.DB)
	if err != nil {
		return err
	}
	roles, err := rolesView(ctx, s.DB)
	if err != nil {
		return err
	}
	errs := []error{s.View.PutRoutes(ctx, routes), s.View.PutConsumer(ctx, consumer)}
	for _, r := range roles {
		errs = append(errs, s.View.PutRole(ctx, r))
	}
	return errors.Join(errs...)
}
