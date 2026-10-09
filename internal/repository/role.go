package repository

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/service"
)

var _ service.RoleRepo = (*Role)(nil)

// Role is the roles and role_permissions tables.
type Role struct{ q db.Querier }

func NewRole(q db.Querier) service.RoleRepo { return &Role{q} }

// roleSelect reads a role with its permissions (GROUP BY r.id after the WHERE).
const roleSelect = `
	SELECT r.id::text, r.name, r.protected, r.grants_all, r.version,
	       coalesce(array_agg(rp.permission_key ORDER BY rp.permission_key) FILTER (WHERE rp.permission_key IS NOT NULL), '{}'),
	       r.created_at, r.updated_at
	FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id`

func (r *Role) List(ctx context.Context, companyID string) ([]service.Role, error) {
	rows, err := r.q.Query(ctx, roleSelect+` WHERE r.company_id = $1 GROUP BY r.id ORDER BY r.name`, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[service.Role])
}

func (r *Role) Find(ctx context.Context, companyID string, ids []string) (map[string]service.Role, error) {
	rows, err := r.q.Query(ctx, roleSelect+` WHERE r.company_id = $1 AND r.id::text = ANY($2) GROUP BY r.id`, companyID, ids)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[service.Role])
	if err != nil {
		return nil, err
	}
	out := make(map[string]service.Role, len(list))
	for _, role := range list {
		out[role.ID] = role
	}
	return out, nil
}

func (r *Role) Lock(ctx context.Context, companyID, id string) (service.Role, error) {
	var locked string
	if err := r.q.QueryRow(ctx, `SELECT id::text FROM roles WHERE id = $1 AND company_id = $2 FOR UPDATE`, id, companyID).Scan(&locked); err != nil {
		return service.Role{}, mapErr(err)
	}
	found, err := r.Find(ctx, companyID, []string{id})
	return found[id], err
}

func (r *Role) Create(ctx context.Context, companyID string, role service.Role) error {
	_, err := r.q.Exec(ctx, `INSERT INTO roles (id, company_id, name, protected, grants_all) VALUES ($1, $2, $3, $4, $5)`,
		role.ID, companyID, role.Name, role.Protected, role.GrantsAll)
	return mapErr(err)
}

func (r *Role) Rename(ctx context.Context, id, name string) error {
	_, err := r.q.Exec(ctx, `UPDATE roles SET name = $2, version = version + 1, updated_at = now() WHERE id = $1`, id, name)
	return mapErr(err)
}

func (r *Role) SetPermissions(ctx context.Context, id string, keys []string) error {
	if _, err := r.q.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, id); err != nil {
		return err
	}
	_, err := r.q.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_key) SELECT $1, unnest($2::text[])`, id, keys)
	return err
}

func (r *Role) Delete(ctx context.Context, id string) error {
	_, err := r.q.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

func (r *Role) Assigned(ctx context.Context, id string) (bool, error) {
	var inUse bool
	err := r.q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM member_roles WHERE role_id = $1)`, id).Scan(&inUse)
	return inUse, err
}

func (r *Role) View(ctx context.Context, ids ...string) ([]service.RoleView, error) {
	rows, err := r.q.Query(ctx, `
		SELECT r.company_id::text, r.id::text,
		       CASE WHEN r.grants_all THEN ARRAY[$1]
		            ELSE coalesce(array_agg(rp.permission_key ORDER BY rp.permission_key)
		                          FILTER (WHERE rp.permission_key IS NOT NULL AND p.deprecated_at IS NULL), '{}') END
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.key = rp.permission_key
		WHERE coalesce(cardinality($2::text[]), 0) = 0 OR r.id::text = ANY($2)
		GROUP BY r.id`, service.AllPermission, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[service.RoleView])
}
