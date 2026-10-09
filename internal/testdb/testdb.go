// Package testdb starts a throwaway Postgres (testcontainers, needs Docker) with Authz's schema.
package testdb

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/tanjed/bus2/authz/internal/db"
)

// Start returns a migrated pool and a function that tears it all down. Call it from TestMain.
func Start(ctx context.Context) (*pgxpool.Pool, func(), error) {
	ctr, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("authz"), tcpostgres.WithUsername("authz"), tcpostgres.WithPassword("authz"),
		tcpostgres.BasicWaitStrategies())
	if err != nil {
		return nil, nil, err
	}
	stop := func() { _ = testcontainers.TerminateContainer(ctr) }
	url, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		stop()
		return nil, nil, err
	}
	pool, err := db.Open(ctx, url)
	if err != nil {
		stop()
		return nil, nil, err
	}
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		stop()
		return nil, nil, err
	}
	return pool, func() { pool.Close(); stop() }, nil
}

// Reset empties every table.
func Reset(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		TRUNCATE invitations, member_roles, members, role_permissions, roles, companies, routes, permissions CASCADE;`)
	if err != nil {
		t.Fatal(err)
	}
}
