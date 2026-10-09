package rbac

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/events"
)

// Caller is the gateway-verified user behind an admin API request (X-Bus-Subject, X-Bus-Company-Id).
type Caller struct {
	Sub       string
	CompanyID string
}

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

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// power is what a caller may hand out: everything (grants_all) or a set of permissions.
type power struct {
	all   bool
	perms map[string]bool
}

// covers is the escalation rule: a role can be created, edited, deleted, assigned or taken away
// only by someone whose own permissions include all of the role's.
func (p power) covers(r Role) bool {
	if p.all {
		return true
	}
	if r.GrantsAll {
		return false
	}
	for _, k := range r.Permissions {
		if !p.perms[k] {
			return false
		}
	}
	return true
}

// callerPower reads the caller's effective permissions fresh from the database (never from the
// token) and confirms they still belong to the company the gateway named.
func callerPower(ctx context.Context, q querier, c Caller) (power, error) {
	if c.Sub == "" || uuid.Validate(c.CompanyID) != nil {
		return power{}, fail(KindForbidden, "not_a_member", "caller is not a member of this company")
	}
	var member bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM members WHERE sub = $1 AND company_id = $2)`, c.Sub, c.CompanyID).Scan(&member); err != nil {
		return power{}, err
	}
	if !member {
		return power{}, fail(KindForbidden, "not_a_member", "caller is not a member of this company")
	}
	rows, err := q.Query(ctx, `
		SELECT r.grants_all, rp.permission_key
		FROM member_roles mr JOIN roles r ON r.id = mr.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE mr.sub = $1`, c.Sub)
	if err != nil {
		return power{}, err
	}
	defer rows.Close()
	p := power{perms: map[string]bool{}}
	for rows.Next() {
		var all bool
		var key *string
		if err := rows.Scan(&all, &key); err != nil {
			return power{}, err
		}
		p.all = p.all || all
		if key != nil {
			p.perms[*key] = true
		}
	}
	return p, rows.Err()
}

const roleSelect = `
	SELECT r.id::text, r.name, r.protected, r.grants_all, r.version,
	       coalesce(array_agg(rp.permission_key ORDER BY rp.permission_key) FILTER (WHERE rp.permission_key IS NOT NULL), '{}'),
	       r.created_at, r.updated_at
	FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id`

func loadRoles(ctx context.Context, q querier, companyID string, ids []string) (map[string]Role, error) {
	rows, err := q.Query(ctx, roleSelect+` WHERE r.company_id = $1 AND r.id::text = ANY($2) GROUP BY r.id`, companyID, ids)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Role])
	if err != nil {
		return nil, err
	}
	out := make(map[string]Role, len(list))
	for _, r := range list {
		out[r.ID] = r
	}
	return out, nil
}

func (s *Service) ListRoles(ctx context.Context, c Caller) ([]Role, error) {
	if _, err := callerPower(ctx, s.DB, c); err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, roleSelect+` WHERE r.company_id = $1 GROUP BY r.id ORDER BY r.name`, c.CompanyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Role])
}

func (s *Service) GetRole(ctx context.Context, c Caller, id string) (Role, error) {
	if _, err := callerPower(ctx, s.DB, c); err != nil {
		return Role{}, err
	}
	roles, err := loadRoles(ctx, s.DB, c.CompanyID, []string{id})
	if err != nil {
		return Role{}, err
	}
	r, ok := roles[id]
	if !ok {
		return Role{}, notFound("role")
	}
	return r, nil
}

// RoleInput is the body of role create and update.
type RoleInput struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// normalize validates the input against the live catalogue.
func (in RoleInput) normalize(ctx context.Context, q querier) (RoleInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > 60 {
		return in, fail(KindInvalid, "invalid_name", "role name must be 1 to 60 characters")
	}
	perms := slices.Clone(in.Permissions)
	slices.Sort(perms)
	perms = slices.Compact(perms)
	for _, k := range perms {
		if !catalogue.ValidPermissionKey(k) {
			return in, fail(KindInvalid, "unknown_permission", "unknown permission %q", k)
		}
	}
	rows, err := q.Query(ctx, `SELECT key FROM permissions WHERE key = ANY($1) AND deprecated_at IS NULL`, perms)
	if err != nil {
		return in, err
	}
	live, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return in, err
	}
	for _, k := range perms {
		if !slices.Contains(live, k) {
			return in, fail(KindInvalid, "unknown_permission", "unknown permission %q", k)
		}
	}
	in.Permissions = perms
	return in, nil
}

func escalation() error {
	return fail(KindForbidden, "escalation", "you can only manage roles whose permissions you hold yourself")
}

func (s *Service) CreateRole(ctx context.Context, c Caller, in RoleInput) (Role, error) {
	var id string
	err := s.write(ctx, func(tx pgx.Tx) error {
		p, err := callerPower(ctx, tx, c)
		if err != nil {
			return err
		}
		if in, err = in.normalize(ctx, tx); err != nil {
			return err
		}
		if !p.covers(Role{Permissions: in.Permissions}) {
			return escalation()
		}
		id = uuid.NewString()
		if _, err := tx.Exec(ctx, `INSERT INTO roles (id, company_id, name) VALUES ($1, $2, $3)`, id, c.CompanyID, in.Name); err != nil {
			if isUniqueViolation(err) {
				return fail(KindConflict, "name_taken", "a role with this name already exists")
			}
			return err
		}
		return setRolePermissions(ctx, tx, id, in.Permissions)
	}, func(ctx context.Context) error {
		return s.putRole(ctx, c.CompanyID, id)
	})
	if err != nil {
		return Role{}, err
	}
	s.Events.Publish(ctx, events.RoleCreated, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "role_id": id, "name": in.Name, "permissions": in.Permissions, "by": c.Sub,
	})
	return s.GetRole(ctx, c, id)
}

func (s *Service) UpdateRole(ctx context.Context, c Caller, id string, in RoleInput) (Role, error) {
	err := s.write(ctx, func(tx pgx.Tx) error {
		p, err := callerPower(ctx, tx, c)
		if err != nil {
			return err
		}
		old, err := lockRole(ctx, tx, c.CompanyID, id)
		if err != nil {
			return err
		}
		if old.Protected {
			return fail(KindPrecondition, "protected_role", "the %s role cannot be changed", old.Name)
		}
		if in, err = in.normalize(ctx, tx); err != nil {
			return err
		}
		if !p.covers(old) || !p.covers(Role{Permissions: in.Permissions}) {
			return escalation()
		}
		if _, err := tx.Exec(ctx, `UPDATE roles SET name = $2, version = version + 1, updated_at = now() WHERE id = $1`, id, in.Name); err != nil {
			if isUniqueViolation(err) {
				return fail(KindConflict, "name_taken", "a role with this name already exists")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, id); err != nil {
			return err
		}
		return setRolePermissions(ctx, tx, id, in.Permissions)
	}, func(ctx context.Context) error {
		return s.putRole(ctx, c.CompanyID, id)
	})
	if err != nil {
		return Role{}, err
	}
	s.Events.Publish(ctx, events.RoleUpdated, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "role_id": id, "name": in.Name, "permissions": in.Permissions, "by": c.Sub,
	})
	return s.GetRole(ctx, c, id)
}

func (s *Service) DeleteRole(ctx context.Context, c Caller, id string) error {
	err := s.write(ctx, func(tx pgx.Tx) error {
		p, err := callerPower(ctx, tx, c)
		if err != nil {
			return err
		}
		old, err := lockRole(ctx, tx, c.CompanyID, id)
		if err != nil {
			return err
		}
		if old.Protected {
			return fail(KindPrecondition, "protected_role", "the %s role cannot be deleted", old.Name)
		}
		if !p.covers(old) {
			return escalation()
		}
		var inUse bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM member_roles WHERE role_id = $1)`, id).Scan(&inUse); err != nil {
			return err
		}
		if inUse {
			return fail(KindPrecondition, "role_in_use", "the role is still assigned; unassign it first")
		}
		_, err = tx.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
		return err
	}, func(ctx context.Context) error {
		return s.View.DeleteRole(ctx, c.CompanyID, id)
	})
	if err != nil {
		return err
	}
	s.Events.Publish(ctx, events.RoleDeleted, c.CompanyID, map[string]any{"company_id": c.CompanyID, "role_id": id, "by": c.Sub})
	return nil
}

// lockRole loads a role of the company and locks it for the rest of the transaction.
func lockRole(ctx context.Context, tx pgx.Tx, companyID, id string) (Role, error) {
	if uuid.Validate(id) != nil {
		return Role{}, notFound("role")
	}
	var locked string
	err := tx.QueryRow(ctx, `SELECT id::text FROM roles WHERE id = $1 AND company_id = $2 FOR UPDATE`, id, companyID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, notFound("role")
	} else if err != nil {
		return Role{}, err
	}
	roles, err := loadRoles(ctx, tx, companyID, []string{id})
	if err != nil {
		return Role{}, err
	}
	return roles[id], nil
}

func setRolePermissions(ctx context.Context, tx pgx.Tx, roleID string, perms []string) error {
	_, err := tx.Exec(ctx, `INSERT INTO role_permissions (role_id, permission_key) SELECT $1, unnest($2::text[])`, roleID, perms)
	return err
}
