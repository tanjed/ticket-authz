package role

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
)

// Repo: every query is scoped by company (invariant 4) except those by a role id already
// checked against the company (Lock, Find).
type Repo interface {
	List(ctx context.Context, companyID string) ([]Role, error)
	// Find returns those of ids that are roles of the company.
	Find(ctx context.Context, companyID string, ids []string) (map[string]Role, error)
	// Lock loads a role of the company and locks it until the transaction ends.
	Lock(ctx context.Context, companyID, id string) (Role, error)
	// Create stores a role (no permissions); ErrDuplicate if the name is taken.
	Create(ctx context.Context, companyID string, r Role) error
	// Rename renames a role and bumps its version; ErrDuplicate if the name is taken.
	Rename(ctx context.Context, id, name string) error
	// SetPermissions replaces a role's permissions.
	SetPermissions(ctx context.Context, id string, keys []string) error
	Delete(ctx context.Context, id string) error
	// Assigned reports whether any member holds the role.
	Assigned(ctx context.Context, id string) (bool, error)
	// View is the gateway view of the given roles, or of every role when ids is empty.
	View(ctx context.Context, ids ...string) ([]cache.RoleView, error)
}

var _ Repo = (*Repository)(nil)

type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Protected   bool      `json:"protected"`
	GrantsAll   bool      `json:"grants_all"`
	Version     int       `json:"version"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Repository is the roles and role_permissions tables.
type Repository struct{ db uow.Querier }

// roleSelect reads a role with its permissions (GROUP BY r.id after the WHERE).
const roleSelect = `
	SELECT r.id::text, r.name, r.protected, r.grants_all, r.version,
	       coalesce(array_agg(rp.permission_key ORDER BY rp.permission_key) FILTER (WHERE rp.permission_key IS NOT NULL), '{}'),
	       r.created_at, r.updated_at
	FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id`

func (r *Repository) List(ctx context.Context, companyID string) ([]Role, error) {
	rows, err := r.db.Q(ctx).Query(ctx, roleSelect+` WHERE r.company_id = $1 GROUP BY r.id ORDER BY r.name`, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Role])
}

func (r *Repository) Find(ctx context.Context, companyID string, ids []string) (map[string]Role, error) {
	rows, err := r.db.Q(ctx).Query(ctx, roleSelect+` WHERE r.company_id = $1 AND r.id::text = ANY($2) GROUP BY r.id`, companyID, ids)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Role])
	if err != nil {
		return nil, err
	}
	out := make(map[string]Role, len(list))
	for _, role := range list {
		out[role.ID] = role
	}
	return out, nil
}

func (r *Repository) Lock(ctx context.Context, companyID, id string) (Role, error) {
	var locked string
	if err := r.db.Q(ctx).QueryRow(ctx, `SELECT id::text FROM roles WHERE id = $1 AND company_id = $2 FOR UPDATE`, id, companyID).Scan(&locked); err != nil {
		return Role{}, apperror.FromPG(err)
	}
	found, err := r.Find(ctx, companyID, []string{id})
	return found[id], err
}

func (r *Repository) Create(ctx context.Context, companyID string, role Role) error {
	_, err := r.db.Q(ctx).Exec(ctx, `INSERT INTO roles (id, company_id, name, protected, grants_all) VALUES ($1, $2, $3, $4, $5)`,
		role.ID, companyID, role.Name, role.Protected, role.GrantsAll)
	return apperror.FromPG(err)
}

func (r *Repository) Rename(ctx context.Context, id, name string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `UPDATE roles SET name = $2, version = version + 1, updated_at = now() WHERE id = $1`, id, name)
	return apperror.FromPG(err)
}

func (r *Repository) SetPermissions(ctx context.Context, id string, keys []string) error {
	if _, err := r.db.Q(ctx).Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, id); err != nil {
		return err
	}
	_, err := r.db.Q(ctx).Exec(ctx, `INSERT INTO role_permissions (role_id, permission_key) SELECT $1, unnest($2::text[])`, id, keys)
	return err
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

func (r *Repository) Assigned(ctx context.Context, id string) (bool, error) {
	var inUse bool
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM member_roles WHERE role_id = $1)`, id).Scan(&inUse)
	return inUse, err
}

func (r *Repository) View(ctx context.Context, ids ...string) ([]cache.RoleView, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT r.company_id::text, r.id::text,
		       CASE WHEN r.grants_all THEN ARRAY[$1]
		            ELSE coalesce(array_agg(rp.permission_key ORDER BY rp.permission_key)
		                          FILTER (WHERE rp.permission_key IS NOT NULL AND p.deprecated_at IS NULL), '{}') END
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.key = rp.permission_key
		WHERE coalesce(cardinality($2::text[]), 0) = 0 OR r.id::text = ANY($2)
		GROUP BY r.id`, cache.AllPermission, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[cache.RoleView])
}
