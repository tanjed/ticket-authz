package resync

import (
	"context"
	"fmt"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// Module provides the resync service and runs it on start (a Redis it cannot write, or a Company
// it cannot reach, fails the boot). Include it after the catalogue module, so the resync publishes
// the seeded manifest.
var Module = fx.Module("service.resync",
	fx.Provide(New),
	fx.Invoke(resyncOnStart),
)

func New(u uow.Transactor, cp cache.Publisher, co company.Client, cat catalogrepo.Repo, roles rolerepo.Repo, users userrepo.Repo) *Service {
	return &Service{uow: u, cache: cp, company: co, catalogue: cat, roles: roles, users: users}
}

func resyncOnStart(lc fx.Lifecycle, svc *Service) {
	lc.Append(fx.StartHook(func(ctx context.Context) error {
		if err := svc.Resync(ctx); err != nil {
			return fmt.Errorf("resync redis: %w", err)
		}
		return nil
	}))
}
