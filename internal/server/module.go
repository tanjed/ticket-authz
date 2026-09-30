package server

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/bundle"
	"github.com/tanjed/bus2/authz/internal/config"
)

// Module runs the four listeners; include it last, so they open after everything else started.
var Module = fx.Module("server",
	fx.Provide(provideServers),
	fx.Invoke(runOnStart),
)

func provideServers(cfg config.Config, admin authzv1.AdminServiceServer, internal authzv1.InternalServiceServer,
	bundles *bundle.Server, pool *pgxpool.Pool, log *slog.Logger) (*Servers, error) {
	return New(Params{Cfg: cfg, Admin: admin, Internal: internal, Bundles: bundles, Pool: pool, Log: log})
}

func runOnStart(lc fx.Lifecycle, sd fx.Shutdowner, s *Servers) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			return s.Start(func(error) { _ = sd.Shutdown(fx.ExitCode(1)) })
		},
		OnStop: func(ctx context.Context) error {
			s.Stop(ctx)
			return nil
		},
	})
}
