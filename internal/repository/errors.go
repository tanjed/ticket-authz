package repository

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/tanjed/bus2/authz/internal/service"
)

// mapErr turns a missing row into service.ErrNotFound and a unique violation into
// service.ErrDuplicate; anything else passes through.
func mapErr(err error) error {
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return service.ErrNotFound
	case errors.As(err, &pg) && pg.Code == "23505":
		return fmt.Errorf("%w: %s", service.ErrDuplicate, pg.ConstraintName)
	default:
		return err
	}
}
