package userrole

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/db/uow"
)

// Repo is what services use from this repository. A user holds roles of one company; who belongs
// to that company is Company's (../Company), not recorded here.
type Repo interface {
	// IsMember reports whether the user holds any role of the company.
	IsMember(ctx context.Context, userID, companyID string) (bool, error)
	// Grants is what the user's roles in the company grant: everything, or these permissions.
	Grants(ctx context.Context, userID, companyID string) (all bool, permissions []string, err error)
	// RoleRefs are the user's roles in the company, for the token.
	RoleRefs(ctx context.Context, userID, companyID string) ([]RoleRef, error)
	// Version is the user's authorization version, 0 if they never held a role.
	Version(ctx context.Context, userID string) (int64, error)
	// List is every user holding roles in the company, with their role ids.
	List(ctx context.Context, companyID string) ([]UserRoles, error)
	// Lock serializes writers of the user's roles and returns their role ids in the company. It
	// attaches the user to the company (user_versions) and drops roles of any other company.
	Lock(ctx context.Context, companyID, userID string) (roleIDs []string, err error)
	// RoleIDs are the ids of the roles the user holds.
	RoleIDs(ctx context.Context, userID string) ([]string, error)
	// AddRoles assigns those of roleIDs that are roles of the company (others are skipped).
	AddRoles(ctx context.Context, companyID, userID string, roleIDs []string) error
	// ReplaceRoles sets the user's roles in the company to roleIDs.
	ReplaceRoles(ctx context.Context, companyID, userID string, roleIDs []string) error
	// DeleteRoles removes every role of the user.
	DeleteRoles(ctx context.Context, userID string) error
	// BumpVersion gives the user a new authorization version (never reused, invariant 10).
	BumpVersion(ctx context.Context, companyID, userID string) (int64, error)
	// OtherHolders counts the company's users other than userID holding the role.
	OtherHolders(ctx context.Context, companyID, roleID, userID string) (int, error)
	// Holds reports whether the user holds the role.
	Holds(ctx context.Context, companyID, roleID, userID string) (bool, error)
	// Versions is every user's authorization version (the boot resync).
	Versions(ctx context.Context) (map[string]int64, error)
}

var _ Repo = (*Repository)(nil)

// UserRoles is a user and the ids of the roles they hold.
type UserRoles struct {
	UserID  string   `json:"user_id"`
	RoleIDs []string `json:"role_ids"`
}

// RoleRef is a role as it appears in the token.
type RoleRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Repository is the user_roles and user_versions tables.
type Repository struct{ db uow.Querier }

func (r *Repository) IsMember(ctx context.Context, userID, companyID string) (bool, error) {
	var ok bool
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_roles WHERE user_id = $1 AND company_id = $2)`, userID, companyID).Scan(&ok)
	return ok, err
}

func (r *Repository) Grants(ctx context.Context, userID, companyID string) (bool, []string, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT r.grants_all, rp.permission_key
		FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE ur.user_id = $1 AND ur.company_id = $2`, userID, companyID)
	if err != nil {
		return false, nil, err
	}
	all := false
	var keys []string
	var grantsAll bool
	var key *string
	_, err = pgx.ForEachRow(rows, []any{&grantsAll, &key}, func() error {
		all = all || grantsAll
		if key != nil {
			keys = append(keys, *key)
		}
		return nil
	})
	return all, keys, err
}

func (r *Repository) RoleRefs(ctx context.Context, userID, companyID string) ([]RoleRef, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT r.id::text, r.name, r.version FROM user_roles ur JOIN roles r ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.company_id = $2 ORDER BY r.name`, userID, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RoleRef])
}

func (r *Repository) Version(ctx context.Context, userID string) (int64, error) {
	var v int64
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT authz_version FROM user_versions WHERE user_id = $1`, userID).Scan(&v)
	if err = apperror.FromPG(err); errors.Is(err, apperror.ErrNotFound) {
		return 0, nil
	}
	return v, err
}

func (r *Repository) List(ctx context.Context, companyID string) ([]UserRoles, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT user_id, array_agg(role_id::text ORDER BY role_id)
		FROM user_roles WHERE company_id = $1 GROUP BY user_id ORDER BY user_id`, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[UserRoles])
}

func (r *Repository) Lock(ctx context.Context, companyID, userID string) ([]string, error) {
	// The upsert locks the user's version row until the transaction ends.
	if _, err := r.db.Q(ctx).Exec(ctx, `
		INSERT INTO user_versions (user_id, company_id, authz_version) VALUES ($1, $2, nextval('authz_versions'))
		ON CONFLICT (user_id) DO UPDATE SET company_id = EXCLUDED.company_id`, userID, companyID); err != nil {
		return nil, err
	}
	if _, err := r.db.Q(ctx).Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND company_id <> $2`, userID, companyID); err != nil {
		return nil, err
	}
	return r.RoleIDs(ctx, userID)
}

func (r *Repository) RoleIDs(ctx context.Context, userID string) ([]string, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT role_id::text FROM user_roles WHERE user_id = $1 ORDER BY role_id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (r *Repository) AddRoles(ctx context.Context, companyID, userID string, roleIDs []string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `
		INSERT INTO user_roles (user_id, company_id, role_id)
		SELECT $1, $2, id FROM roles WHERE company_id = $2 AND id::text = ANY($3)
		ON CONFLICT DO NOTHING`, userID, companyID, roleIDs)
	return err
}

func (r *Repository) ReplaceRoles(ctx context.Context, companyID, userID string, roleIDs []string) error {
	if err := r.DeleteRoles(ctx, userID); err != nil {
		return err
	}
	_, err := r.db.Q(ctx).Exec(ctx, `INSERT INTO user_roles (user_id, company_id, role_id) SELECT $1, $2, unnest($3::uuid[])`, userID, companyID, roleIDs)
	return err
}

func (r *Repository) DeleteRoles(ctx context.Context, userID string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1`, userID)
	return err
}

func (r *Repository) BumpVersion(ctx context.Context, companyID, userID string) (int64, error) {
	var version int64
	err := r.db.Q(ctx).QueryRow(ctx, `
		INSERT INTO user_versions (user_id, company_id, authz_version) VALUES ($1, $2, nextval('authz_versions'))
		ON CONFLICT (user_id) DO UPDATE SET company_id = EXCLUDED.company_id, authz_version = EXCLUDED.authz_version
		RETURNING authz_version`, userID, companyID).Scan(&version)
	return version, err
}

func (r *Repository) OtherHolders(ctx context.Context, companyID, roleID, userID string) (int, error) {
	var n int
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT count(*) FROM user_roles WHERE role_id = $1 AND company_id = $2 AND user_id <> $3`, roleID, companyID, userID).Scan(&n)
	return n, err
}

func (r *Repository) Holds(ctx context.Context, companyID, roleID, userID string) (bool, error) {
	var ok bool
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_roles WHERE role_id = $1 AND company_id = $2 AND user_id = $3)`, roleID, companyID, userID).Scan(&ok)
	return ok, err
}

func (r *Repository) Versions(ctx context.Context) (map[string]int64, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT user_id, authz_version FROM user_versions`)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	var userID string
	var version int64
	_, err = pgx.ForEachRow(rows, []any{&userID, &version}, func() error { out[userID] = version; return nil })
	return out, err
}
