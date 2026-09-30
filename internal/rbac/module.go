package rbac

import (
	"bytes"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/manifest"
)

// Module provides the Service and seeds Authz's own manifest on start.
var Module = fx.Module("rbac",
	fx.Provide(func(pool *pgxpool.Pool, pub events.Publisher, c idp.Client, cfg config.Config) *Service {
		return New(pool, pub, c, cfg.InviteTTL)
	}),
	fx.Invoke(seedOwnManifest),
)

// seedOwnManifest loads the admin API's permissions and routes, as any service's seed Job would.
func seedOwnManifest(lc fx.Lifecycle, svc *Service) {
	lc.Append(fx.StartHook(func(ctx context.Context) error {
		m, err := catalogue.Decode(bytes.NewReader(manifest.JSON))
		if err != nil {
			return fmt.Errorf("own manifest: %w", err)
		}
		if _, err := svc.ApplyManifest(ctx, manifest.Service, m); err != nil {
			return fmt.Errorf("seed own manifest: %w", err)
		}
		return nil
	}))
}
