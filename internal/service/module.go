package service

import (
	"bytes"
	"context"
	"fmt"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/manifest"
)

// Module provides the services, seeds Authz's own manifest on start, then rebuilds the gateway
// view (a Redis it cannot write fails the boot).
var Module = fx.Module("service",
	fx.Provide(
		NewCatalogueService,
		NewCompanyService,
		NewRoleService,
		NewMemberService,
		newInvitationService,
		NewViewService,
	),
	fx.Invoke(seedOwnManifest, rebuildOnStart),
)

func newInvitationService(uow UnitOfWork, view GatewayView, pub events.Publisher, c idp.Client, cfg config.Config,
	invitations InvitationRepoFactory, members MemberRepoFactory, roles RoleRepoFactory, companies CompanyRepoFactory) *InvitationService {
	return NewInvitationService(uow, view, pub, c, cfg.InviteTTL, invitations, members, roles, companies)
}

// seedOwnManifest loads the admin API's permissions and routes, as any service's seed Job would.
func seedOwnManifest(lc fx.Lifecycle, svc *CatalogueService) {
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

func rebuildOnStart(lc fx.Lifecycle, svc *ViewService) {
	lc.Append(fx.StartHook(func(ctx context.Context) error {
		if err := svc.Rebuild(ctx); err != nil {
			return fmt.Errorf("rebuild the gateway view: %w", err)
		}
		return nil
	}))
}
