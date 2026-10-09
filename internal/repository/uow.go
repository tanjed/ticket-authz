// Package repository is Authz's storage: the service layer's ports (service.UnitOfWork and one
// repository per aggregate) over Postgres. SQL lives here and nowhere else.
package repository

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/service"
)

// viewLock serialises Rebuild against writes: writes hold it shared from their transaction until
// their view update is done, Rebuild holds it exclusively, so a rebuild never overwrites a
// concurrent write's update with an older snapshot.
const viewLock = `hashtext('authz.view')`

// viewTimeout bounds a view update: past it the write is logged and left to the next rebuild.
const viewTimeout = 5 * time.Second

var _ service.UnitOfWork = (*UnitOfWork)(nil)

// UnitOfWork runs a service's repository calls together, under the gateway view lock.
type UnitOfWork struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func NewUnitOfWork(pool *pgxpool.Pool, log *slog.Logger) *UnitOfWork {
	return &UnitOfWork{pool: pool, log: log}
}

func (u *UnitOfWork) Write(ctx context.Context, fn func(context.Context, db.Querier) error, project func(context.Context, db.Querier) error) error {
	conn, err := u.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer releaseLocked(conn, `SELECT pg_advisory_unlock_shared(`+viewLock+`)`)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock_shared(`+viewLock+`)`); err != nil {
		return err
	}
	if err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return fn(ctx, tx) }); err != nil {
		return err
	}
	if project == nil {
		return nil
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), viewTimeout)
	defer cancel()
	if err := project(pctx, u.pool); err != nil {
		u.log.Error("gateway view not updated; the next boot rebuilds it", "err", err)
	}
	return nil
}

func (u *UnitOfWork) Read(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	return fn(ctx, u.pool)
}

func (u *UnitOfWork) Snapshot(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	conn, err := u.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer releaseLocked(conn, `SELECT pg_advisory_unlock(`+viewLock+`)`)
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(`+viewLock+`)`); err != nil {
		return err
	}
	return pgx.BeginTxFunc(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error { return fn(ctx, tx) })
}

// releaseLocked runs unlock and returns the connection to the pool, or closes it if the unlock
// failed: a session lock must never stay on a pooled connection.
func releaseLocked(conn *pgxpool.Conn, unlock string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, unlock); err != nil {
		_ = conn.Conn().Close(ctx)
	}
	conn.Release()
}
