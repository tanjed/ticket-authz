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

// Module provides the Postgres pools, the primary (WritePool) and the read replica (ReadPool), and
// applies the migrations on the primary on start, before anything that comes after it in the app
// is started. It also contributes a health probe per pool.
var Module = fx.Module("db",
	fx.Provide(newPools),
	fx.Provide(
		fx.Annotate(writeProbe, fx.ResultTags(health.ProbeGroup)),
		fx.Annotate(readProbe, fx.ResultTags(health.ProbeGroup)),
	),
	fx.Invoke(migrateOnStart),
)

// WritePool is the Postgres primary: writes, migrations, the gateway view rebuild.
type WritePool struct{ *pgxpool.Pool }

// ReadPool is the Postgres read replica: reads outside a write. It is the primary itself when no
// replica is configured.
type ReadPool struct{ *pgxpool.Pool }

// newPools opens the primary and, when it has its own URL, the replica.
func newPools(lc fx.Lifecycle, cfg config.Config) (WritePool, ReadPool, error) {
	write, err := Open(context.Background(), cfg.DatabaseURL)
	if err != nil {
		return WritePool{}, ReadPool{}, err
	}
	lc.Append(fx.StopHook(write.Close))
	if cfg.DatabaseReadURL == cfg.DatabaseURL {
		return WritePool{write}, ReadPool{write}, nil
	}
	read, err := Open(context.Background(), cfg.DatabaseReadURL)
	if err != nil {
		return WritePool{}, ReadPool{}, fmt.Errorf("read replica: %w", err)
	}
	lc.Append(fx.StopHook(read.Close))
	return WritePool{write}, ReadPool{read}, nil
}

// writeProbe and readProbe: each pool answers a ping (the same pool twice when there is no
// replica, which is cheap).
func writeProbe(p WritePool) health.Probe { return health.Probe{Name: "db", Check: p.Ping} }
func readProbe(p ReadPool) health.Probe   { return health.Probe{Name: "db-read", Check: p.Ping} }

func migrateOnStart(lc fx.Lifecycle, pool WritePool, log *slog.Logger) {
	lc.Append(fx.StartHook(func(ctx context.Context) error {
		if err := Migrate(ctx, pool.Pool); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		log.Info("migrations applied")
		return nil
	}))
}
