package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/service"
)

var _ service.MemberRepo = (*Member)(nil)

// Member is the members and member_roles tables.
type Member struct{ q db.Querier }

func NewMember(q db.Querier) service.MemberRepo { return &Member{q} }

func (r *Member) IsMember(ctx context.Context, sub, companyID string) (bool, error) {
	var ok bool
	err := r.q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM members WHERE sub = $1 AND company_id = $2)`, sub, companyID).Scan(&ok)
	return ok, err
}

func (r *Member) Grants(ctx context.Context, sub string) (bool, []string, error) {
	rows, err := r.q.Query(ctx, `
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

func (r *Member) CompanyOf(ctx context.Context, sub string) (string, error) {
	var id string
	err := r.q.QueryRow(ctx, `SELECT company_id::text FROM members WHERE sub = $1`, sub).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (r *Member) Membership(ctx context.Context, sub string) (service.Membership, error) {
	var m service.Membership
	err := r.q.QueryRow(ctx, `
		SELECT m.company_id::text, c.status, m.authz_version FROM members m JOIN companies c ON c.id = m.company_id WHERE m.sub = $1`, sub).
		Scan(&m.CompanyID, &m.CompanyStatus, &m.AuthzVersion)
	return m, mapErr(err)
}

func (r *Member) RoleRefs(ctx context.Context, sub string) ([]service.RoleRef, error) {
	rows, err := r.q.Query(ctx, `
		SELECT r.id::text, r.name, r.version FROM member_roles mr JOIN roles r ON r.id = mr.role_id
		WHERE mr.sub = $1 ORDER BY r.name`, sub)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[service.RoleRef])
}

func (r *Member) List(ctx context.Context, companyID string) ([]service.Member, error) {
	rows, err := r.q.Query(ctx, `
		SELECT m.sub, coalesce(array_agg(mr.role_id::text ORDER BY mr.role_id) FILTER (WHERE mr.role_id IS NOT NULL), '{}'), m.created_at
		FROM members m LEFT JOIN member_roles mr ON mr.sub = m.sub
		WHERE m.company_id = $1 GROUP BY m.sub ORDER BY m.created_at`, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[service.Member])
}

func (r *Member) Create(ctx context.Context, sub, companyID string) (int64, error) {
	var version int64
	err := r.q.QueryRow(ctx, `INSERT INTO members (sub, company_id) VALUES ($1, $2) RETURNING authz_version`, sub, companyID).Scan(&version)
	return version, mapErr(err)
}

func (r *Member) Lock(ctx context.Context, companyID, sub string) ([]string, error) {
	var locked string
	if err := r.q.QueryRow(ctx, `SELECT sub FROM members WHERE sub = $1 AND company_id = $2 FOR UPDATE`, sub, companyID).Scan(&locked); err != nil {
		return nil, mapErr(err)
	}
	rows, err := r.q.Query(ctx, `SELECT role_id::text FROM member_roles WHERE sub = $1 ORDER BY role_id`, sub)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (r *Member) ReplaceRoles(ctx context.Context, companyID, sub string, roleIDs []string) error {
	if _, err := r.q.Exec(ctx, `DELETE FROM member_roles WHERE sub = $1`, sub); err != nil {
		return err
	}
	_, err := r.q.Exec(ctx, `INSERT INTO member_roles (sub, company_id, role_id) SELECT $1, $2, unnest($3::uuid[])`, sub, companyID, roleIDs)
	return err
}

func (r *Member) AddExistingRoles(ctx context.Context, companyID, sub string, roleIDs []string) error {
	_, err := r.q.Exec(ctx, `
		INSERT INTO member_roles (sub, company_id, role_id)
		SELECT $1, $2, id FROM roles WHERE company_id = $2 AND id = ANY($3::uuid[])`, sub, companyID, roleIDs)
	return err
}

func (r *Member) BumpVersion(ctx context.Context, sub string) (int64, error) {
	var version int64
	err := r.q.QueryRow(ctx, `UPDATE members SET authz_version = nextval('authz_versions') WHERE sub = $1 RETURNING authz_version`, sub).Scan(&version)
	return version, err
}

func (r *Member) Delete(ctx context.Context, sub string) error {
	_, err := r.q.Exec(ctx, `DELETE FROM members WHERE sub = $1`, sub)
	return err
}

func (r *Member) OtherHolders(ctx context.Context, companyID, roleID, sub string) (int, error) {
	var n int
	err := r.q.QueryRow(ctx, `SELECT count(*) FROM member_roles WHERE role_id = $1 AND company_id = $2 AND sub <> $3`, roleID, companyID, sub).Scan(&n)
	return n, err
}

func (r *Member) Versions(ctx context.Context) (map[string]int64, error) {
	rows, err := r.q.Query(ctx, `SELECT sub, authz_version FROM members`)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	var sub string
	var version int64
	_, err = pgx.ForEachRow(rows, []any{&sub, &version}, func() error { out[sub] = version; return nil })
	return out, err
}
