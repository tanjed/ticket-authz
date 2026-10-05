package db

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/health"
)

// Module provides the Postgres pool and applies the migrations on start, before anything that
// comes after it in the app is started. It also contributes the "db" health probe.
var Module = fx.Module("db",
	fx.Provide(newPool),
	fx.Provide(fx.Annotate(probe, fx.ResultTags(health.ProbeGroup))),
	fx.Invoke(migrateOnStart),
)

// probe: Postgres answers a ping.
func probe(pool *pgxpool.Pool) health.Probe {
	return health.Probe{Name: "db", Check: pool.Ping}
}

func newPool(lc fx.Lifecycle, cfg config.Config) (*pgxpool.Pool, error) {
	pool, err := Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	lc.Append(fx.StopHook(pool.Close))
	return pool, nil
}

func migrateOnStart(lc fx.Lifecycle, pool *pgxpool.Pool, log *slog.Logger) {
	lc.Append(fx.StartHook(func(ctx context.Context) error {
		if err := Migrate(ctx, pool); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		log.Info("migrations applied")
		return nil
	}))
}
