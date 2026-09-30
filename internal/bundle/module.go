package bundle

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/rbac"
	"github.com/tanjed/bus2/authz/policy"
)

// Module provides the bundle Server and runs the Postgres listener that wakes its long polls.
var Module = fx.Module("bundle",
	fx.Provide(NewHub, provideServer),
	fx.Invoke(listenOnStart),
)

func provideServer(cfg config.Config, svc *rbac.Service, hub *Hub, log *slog.Logger) *Server {
	return &Server{
		Src:       svc,
		Hub:       hub,
		Discovery: Discovery{Service: cfg.BundleService, LongPollSeconds: cfg.LongPollSeconds},
		Policies:  []Policy{{Path: "authz.rego", Source: policy.Rego}},
		// A little above what discovery asks OPA to wait, so OPA's own timeout ends the poll.
		MaxWait: time.Duration(cfg.LongPollSeconds+5) * time.Second,
		Log:     log,
	}
}

func listenOnStart(lc fx.Lifecycle, pool *pgxpool.Pool, hub *Hub, log *slog.Logger) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			go func() {
				defer close(done)
				Listen(ctx, pool, rbac.NotifyChannel, hub, log)
			}()
			return nil
		},
		OnStop: func(stop context.Context) error {
			cancel()
			select {
			case <-done:
			case <-stop.Done():
			}
			return nil
		},
	})
}
