package uow_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/testdb"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	var stop func()
	var err error
	if pool, stop, err = testdb.Start(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "postgres:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

func newUoW(t *testing.T) *uow.UnitOfWork {
	t.Helper()
	testdb.Reset(t, pool)
	return uow.New(db.WritePool{Pool: pool}, db.ReadPool{Pool: testdb.ReadOnly(t, pool)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func companies(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(), `SELECT count(*) FROM companies`).Scan(&n))
	return n
}

func insert(ctx context.Context, u *uow.UnitOfWork, name string) error {
	_, err := u.Q(ctx).Exec(ctx, `INSERT INTO companies (id, name) VALUES (gen_random_uuid(), $1)`, name)
	return err
}

func TestUnitOfWork(t *testing.T) {
	ctx := context.Background()

	t.Run("commits", func(t *testing.T) {
		u := newUoW(t)
		require.NoError(t, u.UnitOfWork(ctx, time.Second, func(ctx context.Context) error {
			require.True(t, uow.InTransaction(ctx))
			return insert(ctx, u, "a")
		}))
		require.Equal(t, 1, companies(t))
	})

	t.Run("rolls back on error", func(t *testing.T) {
		u := newUoW(t)
		boom := errors.New("boom")
		err := u.UnitOfWork(ctx, time.Second, func(ctx context.Context) error {
			require.NoError(t, insert(ctx, u, "a"))
			return boom
		})
		require.ErrorIs(t, err, boom)
		require.Zero(t, companies(t))
	})

	t.Run("nested joins the outer transaction", func(t *testing.T) {
		u := newUoW(t)
		err := u.UnitOfWork(ctx, time.Second, func(ctx context.Context) error {
			require.NoError(t, u.UnitOfWork(ctx, time.Second, func(ctx context.Context) error { return insert(ctx, u, "inner") }))
			return errors.New("outer fails")
		})
		require.Error(t, err)
		require.Zero(t, companies(t), "the inner write is rolled back with the outer one")
	})

	t.Run("timeout must be positive", func(t *testing.T) {
		require.Error(t, newUoW(t).UnitOfWork(ctx, 0, func(context.Context) error { return nil }))
	})

	t.Run("outside a unit of work: the read replica, so a write fails", func(t *testing.T) {
		u := newUoW(t)
		require.False(t, uow.InTransaction(ctx))
		require.Error(t, insert(ctx, u, "stray"))
		require.Zero(t, companies(t))
	})
}
