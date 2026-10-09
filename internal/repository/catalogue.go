package repository

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/service"
)

var _ service.CatalogueRepo = (*Catalogue)(nil)

// Catalogue is the permissions and routes tables.
type Catalogue struct{ q db.Querier }

func NewCatalogue(q db.Querier) service.CatalogueRepo { return &Catalogue{q} }

func (r *Catalogue) LockManifests(ctx context.Context) error {
	_, err := r.q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('authz.manifests'))`)
	return err
}

func (r *Catalogue) PermissionOwner(ctx context.Context, keys []string, svc string) (key, owner string, err error) {
	err = r.q.QueryRow(ctx, `SELECT key, service FROM permissions WHERE key = ANY($1) AND service <> $2 LIMIT 1`, keys, svc).Scan(&key, &owner)
	return key, owner, mapErr(err)
}

func (r *Catalogue) RouteOwner(ctx context.Context, names []string, svc string) (name, owner string, err error) {
	err = r.q.QueryRow(ctx, `SELECT name, service FROM routes WHERE name = ANY($1) AND service <> $2 LIMIT 1`, names, svc).Scan(&name, &owner)
	return name, owner, mapErr(err)
}

func (r *Catalogue) UpsertPermission(ctx context.Context, svc string, p catalogue.Permission) (bool, error) {
	tag, err := r.q.Exec(ctx, `
		INSERT INTO permissions (key, service, description, consumer) VALUES ($1, $2, $3, $4)
		ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description, consumer = EXCLUDED.consumer, deprecated_at = NULL
		WHERE (permissions.description, permissions.consumer, permissions.deprecated_at)
		      IS DISTINCT FROM (EXCLUDED.description, EXCLUDED.consumer, NULL::timestamptz)`,
		p.Key, svc, p.Description, p.Consumer)
	return tag.RowsAffected() > 0, err
}

func (r *Catalogue) UpsertRoute(ctx context.Context, svc string, rt catalogue.Route) (bool, error) {
	var perm *string
	if !rt.Public {
		perm = &rt.Permission
	}
	tag, err := r.q.Exec(ctx, `
		INSERT INTO routes (name, service, permission_key, public) VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO UPDATE SET permission_key = EXCLUDED.permission_key, public = EXCLUDED.public, deprecated_at = NULL
		WHERE (routes.permission_key, routes.public, routes.deprecated_at)
		      IS DISTINCT FROM (EXCLUDED.permission_key, EXCLUDED.public, NULL::timestamptz)`,
		rt.Name, svc, perm, rt.Public)
	return tag.RowsAffected() > 0, err
}

func (r *Catalogue) DeprecatePermissions(ctx context.Context, svc string, keep []string) (int64, error) {
	tag, err := r.q.Exec(ctx, `UPDATE permissions SET deprecated_at = now() WHERE service = $1 AND deprecated_at IS NULL AND NOT (key = ANY($2))`, svc, keep)
	return tag.RowsAffected(), err
}

func (r *Catalogue) DeprecateRoutes(ctx context.Context, svc string, keep []string) (int64, error) {
	tag, err := r.q.Exec(ctx, `UPDATE routes SET deprecated_at = now() WHERE service = $1 AND deprecated_at IS NULL AND NOT (name = ANY($2))`, svc, keep)
	return tag.RowsAffected(), err
}

func (r *Catalogue) Live(ctx context.Context) ([]service.PermissionInfo, error) {
	rows, err := r.q.Query(ctx, `SELECT key, service, description FROM permissions WHERE deprecated_at IS NULL ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[service.PermissionInfo])
}

func (r *Catalogue) LiveKeys(ctx context.Context, keys []string) ([]string, error) {
	rows, err := r.q.Query(ctx, `SELECT key FROM permissions WHERE key = ANY($1) AND deprecated_at IS NULL`, keys)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// RoutesView is every live route. A route whose permission is deprecated is left out, so it is
// denied.
func (r *Catalogue) RoutesView(ctx context.Context) (map[string]string, error) {
	rows, err := r.q.Query(ctx, `
		SELECT r.name, coalesce(r.permission_key, $1) FROM routes r
		LEFT JOIN permissions p ON p.key = r.permission_key
		WHERE r.deprecated_at IS NULL AND (r.public OR p.deprecated_at IS NULL)`, service.RoutePublic)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var name, value string
	_, err = pgx.ForEachRow(rows, []any{&name, &value}, func() error { out[name] = value; return nil })
	return out, err
}

func (r *Catalogue) ConsumerView(ctx context.Context) ([]string, error) {
	rows, err := r.q.Query(ctx, `SELECT key FROM permissions WHERE consumer AND deprecated_at IS NULL ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
