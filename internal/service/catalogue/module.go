package catalogue

import (
	"bytes"
	"context"
	"fmt"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	"github.com/tanjed/bus2/authz/manifest"
)

// Module provides the catalogue service and seeds Authz's own manifest on start.
var Module = fx.Module("service.catalogue",
	fx.Provide(New),
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

func New(u uow.Transactor, cp cache.Publisher, cat catalogrepo.Repo, roles rolerepo.Repo) *Service {
	return &Service{uow: u, cache: cp, catalogue: cat, roles: roles}
}
