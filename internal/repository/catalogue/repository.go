package catalogue

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/db/uow"
)

// Repo is the permissions and routes services declare in their manifests.
type Repo interface {
	// LockManifests serialises manifest applies until the transaction ends.
	LockManifests(ctx context.Context) error
	// PermissionOwner returns the first of keys owned by a service other than service.
	PermissionOwner(ctx context.Context, keys []string, service string) (key, owner string, err error)
	// RouteOwner returns the first of names owned by a service other than service.
	RouteOwner(ctx context.Context, names []string, service string) (name, owner string, err error)
	// UpsertPermission and UpsertRoute store one entry (and undeprecate it); changed is false
	// when it was stored as is.
	UpsertPermission(ctx context.Context, service string, p catalogue.Permission) (changed bool, err error)
	UpsertRoute(ctx context.Context, service string, r catalogue.Route) (changed bool, err error)
	// DeprecatePermissions and DeprecateRoutes deprecate the service's live entries not in keep.
	DeprecatePermissions(ctx context.Context, service string, keep []string) (int64, error)
	DeprecateRoutes(ctx context.Context, service string, keep []string) (int64, error)
	// Live lists the live permissions; LiveKeys is those of keys that are live.
	Live(ctx context.Context) ([]PermissionInfo, error)
	LiveKeys(ctx context.Context, keys []string) ([]string, error)
	// RoutesView and ConsumerView are the catalogue's published state.
	RoutesView(ctx context.Context) (map[string]string, error)
	ConsumerView(ctx context.Context) ([]string, error)
}

var _ Repo = (*Repository)(nil)

// PermissionInfo is one catalogue entry, as the admin API lists it.
type PermissionInfo struct {
	Key         string `json:"key"`
	Service     string `json:"service"`
	Description string `json:"description"`
}

// Repository is the permissions and routes tables.
type Repository struct{ db uow.Querier }

func (r *Repository) LockManifests(ctx context.Context) error {
	_, err := r.db.Q(ctx).Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('authz.manifests'))`)
	return err
}

func (r *Repository) PermissionOwner(ctx context.Context, keys []string, svc string) (key, owner string, err error) {
	err = r.db.Q(ctx).QueryRow(ctx, `SELECT key, service FROM permissions WHERE key = ANY($1) AND service <> $2 LIMIT 1`, keys, svc).Scan(&key, &owner)
	return key, owner, apperror.FromPG(err)
}

func (r *Repository) RouteOwner(ctx context.Context, names []string, svc string) (name, owner string, err error) {
	err = r.db.Q(ctx).QueryRow(ctx, `SELECT name, service FROM routes WHERE name = ANY($1) AND service <> $2 LIMIT 1`, names, svc).Scan(&name, &owner)
	return name, owner, apperror.FromPG(err)
}

func (r *Repository) UpsertPermission(ctx context.Context, svc string, p catalogue.Permission) (bool, error) {
	tag, err := r.db.Q(ctx).Exec(ctx, `
		INSERT INTO permissions (key, service, description, consumer) VALUES ($1, $2, $3, $4)
		ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description, consumer = EXCLUDED.consumer, deprecated_at = NULL
		WHERE (permissions.description, permissions.consumer, permissions.deprecated_at)
		      IS DISTINCT FROM (EXCLUDED.description, EXCLUDED.consumer, NULL::timestamptz)`,
		p.Key, svc, p.Description, p.Consumer)
	return tag.RowsAffected() > 0, err
}

func (r *Repository) UpsertRoute(ctx context.Context, svc string, rt catalogue.Route) (bool, error) {
	var perm *string
	if rt.Permission != "" {
		perm = &rt.Permission
	}
	tag, err := r.db.Q(ctx).Exec(ctx, `
		INSERT INTO routes (name, service, permission_key, public, authenticated) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (name) DO UPDATE SET permission_key = EXCLUDED.permission_key, public = EXCLUDED.public,
		  authenticated = EXCLUDED.authenticated, deprecated_at = NULL
		WHERE (routes.permission_key, routes.public, routes.authenticated, routes.deprecated_at)
		      IS DISTINCT FROM (EXCLUDED.permission_key, EXCLUDED.public, EXCLUDED.authenticated, NULL::timestamptz)`,
		rt.Name, svc, perm, rt.Public, rt.Authenticated)
	return tag.RowsAffected() > 0, err
}

func (r *Repository) DeprecatePermissions(ctx context.Context, svc string, keep []string) (int64, error) {
	tag, err := r.db.Q(ctx).Exec(ctx, `UPDATE permissions SET deprecated_at = now() WHERE service = $1 AND deprecated_at IS NULL AND NOT (key = ANY($2))`, svc, keep)
	return tag.RowsAffected(), err
}

func (r *Repository) DeprecateRoutes(ctx context.Context, svc string, keep []string) (int64, error) {
	tag, err := r.db.Q(ctx).Exec(ctx, `UPDATE routes SET deprecated_at = now() WHERE service = $1 AND deprecated_at IS NULL AND NOT (name = ANY($2))`, svc, keep)
	return tag.RowsAffected(), err
}

func (r *Repository) Live(ctx context.Context) ([]PermissionInfo, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT key, service, description FROM permissions WHERE deprecated_at IS NULL ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[PermissionInfo])
}

func (r *Repository) LiveKeys(ctx context.Context, keys []string) ([]string, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT key FROM permissions WHERE key = ANY($1) AND deprecated_at IS NULL`, keys)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// RoutesView is every live route. A route whose permission is deprecated is left out, so it is
// denied.
func (r *Repository) RoutesView(ctx context.Context) (map[string]string, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT r.name, CASE WHEN r.public THEN $1 WHEN r.authenticated THEN $2 ELSE r.permission_key END
		FROM routes r
		LEFT JOIN permissions p ON p.key = r.permission_key
		WHERE r.deprecated_at IS NULL AND (r.public OR r.authenticated OR p.deprecated_at IS NULL)`,
		cache.RoutePublic, cache.RouteAuthenticated)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var name, value string
	_, err = pgx.ForEachRow(rows, []any{&name, &value}, func() error { out[name] = value; return nil })
	return out, err
}

func (r *Repository) ConsumerView(ctx context.Context) ([]string, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT key FROM permissions WHERE consumer AND deprecated_at IS NULL ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
