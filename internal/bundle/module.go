package bundle

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/rbac"
	"github.com/tanjed/bus2/authz/policy"
)

// Tag is the name the bundle endpoint (an http.Handler) is provided under.
const Tag = `name:"bundles"`

// Module provides the bundle Server (BundleService reads it), also as the OPA endpoint: an
// http.Handler tagged bundles. It reads the domain as a Source, and runs the Postgres listener
// that wakes the long polls.
var Module = fx.Module("bundle",
	fx.Provide(
		NewHub,
		fx.Annotate(func(s *rbac.Service) *rbac.Service { return s }, fx.As(new(Source))),
		provideServer,
		fx.Annotate(func(s *Server) *Server { return s }, fx.As(new(http.Handler)), fx.ResultTags(Tag)),
	),
	fx.Invoke(listenOnStart),
)

// provideServer fails the boot on an unreadable or invalid signing key, or a policy that does not
// parse: either would leave every gateway refusing the bundles.
func provideServer(cfg config.Config, src Source, hub *Hub, log *slog.Logger) (*Server, error) {
	key, err := os.ReadFile(cfg.BundleSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("bundle signing key: %w", err)
	}
	signer, err := NewSigner(key, cfg.BundleSigningKeyID)
	if err != nil {
		return nil, err
	}
	policies := []Policy{{Path: "authz.rego", Source: policy.Rego}}
	if err := ParsePolicies(policies); err != nil {
		return nil, err
	}
	return &Server{
		Src:       src,
		Hub:       hub,
		Discovery: Discovery{Service: cfg.BundleService, LongPollSeconds: cfg.LongPollSeconds},
		Policies:  policies,
		Signer:    signer,
		// A little above what discovery asks OPA to wait, so OPA's own timeout ends the poll.
		MaxWait: time.Duration(cfg.LongPollSeconds+5) * time.Second,
		Log:     log,
	}, nil
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
