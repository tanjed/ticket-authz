package member

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/db/uow"
)

// Repo is what services use from this repository.
type Repo interface {
	IsMember(ctx context.Context, sub, companyID string) (bool, error)
	// Grants is what a subject's roles grant: everything, or these permissions.
	Grants(ctx context.Context, sub string) (all bool, permissions []string, err error)
	// CompanyOf is the subject's company, or "" if none.
	CompanyOf(ctx context.Context, sub string) (string, error)
	// Membership is the subject's company, its status and the subject's authorization version.
	Membership(ctx context.Context, sub string) (Membership, error)
	RoleRefs(ctx context.Context, sub string) ([]RoleRef, error)
	List(ctx context.Context, companyID string) ([]Member, error)
	// Create adds a member and returns its authorization version; ErrDuplicate if the subject
	// already belongs to a company.
	Create(ctx context.Context, sub, companyID string) (version int64, err error)
	// Lock locks a member of the company and returns their role ids.
	Lock(ctx context.Context, companyID, sub string) (roleIDs []string, err error)
	// ReplaceRoles sets the member's roles to roleIDs.
	ReplaceRoles(ctx context.Context, companyID, sub string, roleIDs []string) error
	// AddExistingRoles assigns those of roleIDs that are still roles of the company.
	AddExistingRoles(ctx context.Context, companyID, sub string, roleIDs []string) error
	// BumpVersion gives the member a new authorization version (never reused, invariant 10).
	BumpVersion(ctx context.Context, sub string) (int64, error)
	Delete(ctx context.Context, sub string) error
	// OtherHolders counts the company's members other than sub holding the role.
	OtherHolders(ctx context.Context, companyID, roleID, sub string) (int, error)
	// Versions is every member's authorization version (the boot resync).
	Versions(ctx context.Context) (map[string]int64, error)
}

var _ Repo = (*Repository)(nil)

type Member struct {
	Sub       string    `json:"sub"`
	RoleIDs   []string  `json:"role_ids"`
	CreatedAt time.Time `json:"created_at"`
}

// Membership is a subject's company, its status and the subject's authorization version.
type Membership struct {
	CompanyID     string
	CompanyStatus string
	AuthzVersion  int64
}

// RoleRef is a role as it appears in the token.
type RoleRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Repository is the members and member_roles tables.
type Repository struct{ db uow.Querier }

func (r *Repository) IsMember(ctx context.Context, sub, companyID string) (bool, error) {
	var ok bool
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM members WHERE sub = $1 AND company_id = $2)`, sub, companyID).Scan(&ok)
	return ok, err
}

func (r *Repository) Grants(ctx context.Context, sub string) (bool, []string, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT r.grants_all, rp.permission_key
		FROM member_roles mr JOIN roles r ON r.id = mr.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		WHERE mr.sub = $1`, sub)
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

func (r *Repository) CompanyOf(ctx context.Context, sub string) (string, error) {
	var id string
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT company_id::text FROM members WHERE sub = $1`, sub).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (r *Repository) Membership(ctx context.Context, sub string) (Membership, error) {
	var m Membership
	err := r.db.Q(ctx).QueryRow(ctx, `
		SELECT m.company_id::text, c.status, m.authz_version FROM members m JOIN companies c ON c.id = m.company_id WHERE m.sub = $1`, sub).
		Scan(&m.CompanyID, &m.CompanyStatus, &m.AuthzVersion)
	return m, apperror.FromPG(err)
}

func (r *Repository) RoleRefs(ctx context.Context, sub string) ([]RoleRef, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT r.id::text, r.name, r.version FROM member_roles mr JOIN roles r ON r.id = mr.role_id
		WHERE mr.sub = $1 ORDER BY r.name`, sub)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RoleRef])
}

func (r *Repository) List(ctx context.Context, companyID string) ([]Member, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `
		SELECT m.sub, coalesce(array_agg(mr.role_id::text ORDER BY mr.role_id) FILTER (WHERE mr.role_id IS NOT NULL), '{}'), m.created_at
		FROM members m LEFT JOIN member_roles mr ON mr.sub = m.sub
		WHERE m.company_id = $1 GROUP BY m.sub ORDER BY m.created_at`, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Member])
}

func (r *Repository) Create(ctx context.Context, sub, companyID string) (int64, error) {
	var version int64
	err := r.db.Q(ctx).QueryRow(ctx, `INSERT INTO members (sub, company_id) VALUES ($1, $2) RETURNING authz_version`, sub, companyID).Scan(&version)
	return version, apperror.FromPG(err)
}

func (r *Repository) Lock(ctx context.Context, companyID, sub string) ([]string, error) {
	var locked string
	if err := r.db.Q(ctx).QueryRow(ctx, `SELECT sub FROM members WHERE sub = $1 AND company_id = $2 FOR UPDATE`, sub, companyID).Scan(&locked); err != nil {
		return nil, apperror.FromPG(err)
	}
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT role_id::text FROM member_roles WHERE sub = $1 ORDER BY role_id`, sub)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (r *Repository) ReplaceRoles(ctx context.Context, companyID, sub string, roleIDs []string) error {
	if _, err := r.db.Q(ctx).Exec(ctx, `DELETE FROM member_roles WHERE sub = $1`, sub); err != nil {
		return err
	}
	_, err := r.db.Q(ctx).Exec(ctx, `INSERT INTO member_roles (sub, company_id, role_id) SELECT $1, $2, unnest($3::uuid[])`, sub, companyID, roleIDs)
	return err
}

func (r *Repository) AddExistingRoles(ctx context.Context, companyID, sub string, roleIDs []string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `
		INSERT INTO member_roles (sub, company_id, role_id)
		SELECT $1, $2, id FROM roles WHERE company_id = $2 AND id = ANY($3::uuid[])`, sub, companyID, roleIDs)
	return err
}

func (r *Repository) BumpVersion(ctx context.Context, sub string) (int64, error) {
	var version int64
	err := r.db.Q(ctx).QueryRow(ctx, `UPDATE members SET authz_version = nextval('authz_versions') WHERE sub = $1 RETURNING authz_version`, sub).Scan(&version)
	return version, err
}

func (r *Repository) Delete(ctx context.Context, sub string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `DELETE FROM members WHERE sub = $1`, sub)
	return err
}

func (r *Repository) OtherHolders(ctx context.Context, companyID, roleID, sub string) (int, error) {
	var n int
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT count(*) FROM member_roles WHERE role_id = $1 AND company_id = $2 AND sub <> $3`, roleID, companyID, sub).Scan(&n)
	return n, err
}

func (r *Repository) Versions(ctx context.Context) (map[string]int64, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT sub, authz_version FROM members`)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	var sub string
	var version int64
	_, err = pgx.ForEachRow(rows, []any{&sub, &version}, func() error { out[sub] = version; return nil })
	return out, err
}
