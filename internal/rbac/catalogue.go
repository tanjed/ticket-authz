package rbac

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/catalogue"
)

// ManifestResult summarises an applied manifest.
type ManifestResult struct {
	Service     string `json:"service"`
	Permissions int    `json:"permissions"`
	Routes      int    `json:"routes"`
	// Changed is false when the manifest matched what was stored (bundles untouched).
	Changed bool `json:"changed"`
}

// ApplyManifest replaces a service's permissions and routes. Anything the service no longer lists
// is deprecated, never deleted (role links survive a rollback); listing it again restores it.
func (s *Service) ApplyManifest(ctx context.Context, service string, m catalogue.Manifest) (ManifestResult, error) {
	if !catalogue.ValidService(service) {
		return ManifestResult{}, fail(KindInvalid, "invalid_service", "invalid service name %q", service)
	}
	if err := m.Validate(); err != nil {
		return ManifestResult{}, fail(KindInvalid, "invalid_manifest", "%s", err.Error())
	}
	keys := make([]string, 0, len(m.Permissions))
	for _, p := range m.Permissions {
		keys = append(keys, p.Key)
	}
	names := make([]string, 0, len(m.Routes))
	for _, r := range m.Routes {
		names = append(names, r.Name)
	}

	res := ManifestResult{Service: service, Permissions: len(keys), Routes: len(names)}
	err := s.tx(ctx, func(tx pgx.Tx) error {
		// Seeds from several services may run at once; ownership checks need them serialised.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('authz.manifests'))`); err != nil {
			return err
		}
		var key, owner string
		err := tx.QueryRow(ctx, `SELECT key, service FROM permissions WHERE key = ANY($1) AND service <> $2 LIMIT 1`, keys, service).Scan(&key, &owner)
		if err == nil {
			return fail(KindConflict, "owned_elsewhere", "permission %q belongs to service %q", key, owner)
		} else if err != pgx.ErrNoRows {
			return err
		}
		err = tx.QueryRow(ctx, `SELECT name, service FROM routes WHERE name = ANY($1) AND service <> $2 LIMIT 1`, names, service).Scan(&key, &owner)
		if err == nil {
			return fail(KindConflict, "owned_elsewhere", "route %q belongs to service %q", key, owner)
		} else if err != pgx.ErrNoRows {
			return err
		}

		var changed int64
		for _, p := range m.Permissions {
			tag, err := tx.Exec(ctx, `
				INSERT INTO permissions (key, service, description, consumer) VALUES ($1, $2, $3, $4)
				ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description, consumer = EXCLUDED.consumer, deprecated_at = NULL
				WHERE (permissions.description, permissions.consumer, permissions.deprecated_at)
				      IS DISTINCT FROM (EXCLUDED.description, EXCLUDED.consumer, NULL::timestamptz)`,
				p.Key, service, p.Description, p.Consumer)
			if err != nil {
				return err
			}
			changed += tag.RowsAffected()
		}
		for _, r := range m.Routes {
			var perm *string
			if !r.Public {
				perm = &r.Permission
			}
			tag, err := tx.Exec(ctx, `
				INSERT INTO routes (name, service, permission_key, public) VALUES ($1, $2, $3, $4)
				ON CONFLICT (name) DO UPDATE SET permission_key = EXCLUDED.permission_key, public = EXCLUDED.public, deprecated_at = NULL
				WHERE (routes.permission_key, routes.public, routes.deprecated_at)
				      IS DISTINCT FROM (EXCLUDED.permission_key, EXCLUDED.public, NULL::timestamptz)`,
				r.Name, service, perm, r.Public)
			if err != nil {
				return err
			}
			changed += tag.RowsAffected()
		}
		tag, err := tx.Exec(ctx, `UPDATE routes SET deprecated_at = now() WHERE service = $1 AND deprecated_at IS NULL AND NOT (name = ANY($2))`, service, names)
		if err != nil {
			return err
		}
		changed += tag.RowsAffected()
		tag, err = tx.Exec(ctx, `UPDATE permissions SET deprecated_at = now() WHERE service = $1 AND deprecated_at IS NULL AND NOT (key = ANY($2))`, service, keys)
		if err != nil {
			return err
		}
		changed += tag.RowsAffected()

		if res.Changed = changed > 0; res.Changed {
			return bump(ctx, tx, BundleCatalogue, BundleConsumer)
		}
		return nil
	})
	return res, err
}

// PermissionInfo is one catalogue entry, as the admin API lists it.
type PermissionInfo struct {
	Key         string `json:"key"`
	Service     string `json:"service"`
	Description string `json:"description"`
}

// Permissions lists the live catalogue (what roles can be built from).
func (s *Service) Permissions(ctx context.Context) ([]PermissionInfo, error) {
	rows, err := s.DB.Query(ctx, `SELECT key, service, description FROM permissions WHERE deprecated_at IS NULL ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[PermissionInfo])
}
