// Package uow is the unit of work: it runs a service's repository calls in one transaction and
// carries the transaction in the context. Repositories never hold a connection: they run every
// query on Q(ctx), which is the transaction inside a unit of work and the read replica outside
// one (so a write that forgets its unit of work fails loudly: the replica is read-only).
//
//	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
//		return s.roles.Create(ctx, ...) // in the transaction
//	})
package uow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tanjed/bus2/authz/internal/db"
)

// Timeout is the default bound of one unit of work.
const Timeout = 10 * time.Second

// Transactor is what services use.
type Transactor interface {
	// UnitOfWork runs fn in one transaction on the primary and commits if fn returns nil. Inside
	// another unit of work it joins it, and the outermost one commits.
	UnitOfWork(ctx context.Context, timeout time.Duration, fn func(ctx context.Context) error) error
}

// Querier is what repositories use.
type Querier interface {
	// Q is the transaction the context carries, or the read replica outside a unit of work.
	Q(ctx context.Context) db.Querier
}

var (
	_ Transactor = (*UnitOfWork)(nil)
	_ Querier    = (*UnitOfWork)(nil)
)

// UnitOfWork is both.
type UnitOfWork struct {
	write *pgxpool.Pool
	read  *pgxpool.Pool
	log   *slog.Logger
}

type ctxKey struct{}

// InTransaction reports whether ctx carries a unit of work's transaction.
func InTransaction(ctx context.Context) bool {
	_, ok := ctx.Value(ctxKey{}).(pgx.Tx)
	return ok
}

func (u *UnitOfWork) Q(ctx context.Context) db.Querier {
	if tx, ok := ctx.Value(ctxKey{}).(pgx.Tx); ok {
		return tx
	}
	return u.read
}

func (u *UnitOfWork) UnitOfWork(ctx context.Context, timeout time.Duration, fn func(ctx context.Context) error) error {
	// Already inside a transaction: join it and let the outermost call commit.
	if InTransaction(ctx) {
		return fn(ctx)
	}

	if timeout <= 0 {
		return errors.New("unitofwork: timeout must be > 0")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tx, err := u.write.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("unitofwork: begin transaction: %w", err)
	}
	// Safety net: rolls back on any early return. After a successful Commit this is a no-op that
	// returns pgx.ErrTxClosed, which we deliberately ignore; any other rollback failure is logged
	// (it never masks the error already being returned).
	defer func() {
		if err := tx.Rollback(context.WithoutCancel(ctx)); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			u.log.Error("unitofwork: rollback failed", "error", err)
		}
	}()

	if err := fn(context.WithValue(ctx, ctxKey{}, tx)); err != nil {
		return err
	}

	// fn may have returned nil while the deadline elapsed mid-flight; don't commit a transaction
	// whose connection the driver has already cancelled.
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("unitofwork: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("unitofwork: commit: %w", err)
	}
	return nil
}
