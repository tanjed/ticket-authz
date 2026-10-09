package repository

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/service"
)

var _ service.CompanyRepo = (*Company)(nil)

// Company is the companies table.
type Company struct{ q db.Querier }

func NewCompany(q db.Querier) service.CompanyRepo { return &Company{q} }

func (r *Company) Create(ctx context.Context, id, name string) error {
	_, err := r.q.Exec(ctx, `INSERT INTO companies (id, name) VALUES ($1, $2)`, id, name)
	return mapErr(err)
}

func (r *Company) SetStatus(ctx context.Context, id, status string) (bool, error) {
	tag, err := r.q.Exec(ctx, `UPDATE companies SET status = $2 WHERE id = $1 AND status <> $2`, id, status)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	var exists bool
	if err := r.q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM companies WHERE id = $1)`, id).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, service.ErrNotFound
	}
	return false, nil
}

func (r *Company) Name(ctx context.Context, id string) (string, error) {
	var name string
	err := r.q.QueryRow(ctx, `SELECT name FROM companies WHERE id = $1`, id).Scan(&name)
	return name, mapErr(err)
}

func (r *Company) Statuses(ctx context.Context) (map[string]string, error) {
	rows, err := r.q.Query(ctx, `SELECT id::text, status FROM companies`)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var id, status string
	_, err = pgx.ForEachRow(rows, []any{&id, &status}, func() error { out[id] = status; return nil })
	return out, err
}
