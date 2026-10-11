package resync

import (
	"context"
	"fmt"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	companyrepo "github.com/tanjed/bus2/authz/internal/repository/company"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// Module provides the resync service and runs it on start (a Redis it cannot write fails the
// boot). Include it after the catalogue module, so the resync publishes the seeded manifest.
var Module = fx.Module("service.resync",
	fx.Provide(New),
	fx.Invoke(resyncOnStart),
)

func New(u uow.Transactor, cp cache.Publisher, cat catalogrepo.Repo, roles rolerepo.Repo, companies companyrepo.Repo, members memberrepo.Repo) *Service {
	return &Service{uow: u, cache: cp, catalogue: cat, roles: roles, companies: companies, members: members}
}

func resyncOnStart(lc fx.Lifecycle, svc *Service) {
	lc.Append(fx.StartHook(func(ctx context.Context) error {
		if err := svc.Resync(ctx); err != nil {
			return fmt.Errorf("resync redis: %w", err)
		}
		return nil
	}))
}
