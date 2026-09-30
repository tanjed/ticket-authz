// Package db opens the Postgres pool and runs migrations.
package db

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/tanjed/bus2/authz/migrations"
)

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres: %w", err)
	}
	return pool, nil
}

// Migrate applies every pending migration. It runs at every boot; a Postgres advisory lock
// serialises replicas starting together.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	sqlDB := stdlib.OpenDBFromPool(pool)
	defer sqlDB.Close()
	return migrate(ctx, sqlDB)
}

func migrate(ctx context.Context, sqlDB *sql.DB) error {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return err
	}
	p, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations.FS, goose.WithSessionLocker(locker))
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}
