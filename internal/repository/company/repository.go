package company

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/db/uow"
)

// Repo is what services use from this repository.
type Repo interface {
	Create(ctx context.Context, id, name string) error
	// SetStatus reports whether the status changed; ErrNotFound if there is no such company.
	SetStatus(ctx context.Context, id, status string) (changed bool, err error)
	Name(ctx context.Context, id string) (string, error)
	// Statuses is every company's status (the boot resync).
	Statuses(ctx context.Context) (map[string]string, error)
}

var _ Repo = (*Repository)(nil)

// Repository is the companies table.
type Repository struct{ db uow.Querier }

func (r *Repository) Create(ctx context.Context, id, name string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `INSERT INTO companies (id, name) VALUES ($1, $2)`, id, name)
	return apperror.FromPG(err)
}

func (r *Repository) SetStatus(ctx context.Context, id, status string) (bool, error) {
	tag, err := r.db.Q(ctx).Exec(ctx, `UPDATE companies SET status = $2 WHERE id = $1 AND status <> $2`, id, status)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	var exists bool
	if err := r.db.Q(ctx).QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM companies WHERE id = $1)`, id).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, apperror.ErrNotFound
	}
	return false, nil
}

func (r *Repository) Name(ctx context.Context, id string) (string, error) {
	var name string
	err := r.db.Q(ctx).QueryRow(ctx, `SELECT name FROM companies WHERE id = $1`, id).Scan(&name)
	return name, apperror.FromPG(err)
}

func (r *Repository) Statuses(ctx context.Context) (map[string]string, error) {
	rows, err := r.db.Q(ctx).Query(ctx, `SELECT id::text, status FROM companies`)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var id, status string
	_, err = pgx.ForEachRow(rows, []any{&id, &status}, func() error { out[id] = status; return nil })
	return out, err
}
