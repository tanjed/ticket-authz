package apperror

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// FromPG turns a missing row into ErrNotFound and a unique violation into
// ErrDuplicate; anything else passes through.
func FromPG(err error) error {
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNotFound
	case errors.As(err, &pg) && pg.Code == "23505":
		return fmt.Errorf("%w: %s", ErrDuplicate, pg.ConstraintName)
	default:
		return err
	}
}
