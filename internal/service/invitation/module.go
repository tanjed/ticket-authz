package invitation

import (
	"time"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
	companyrepo "github.com/tanjed/bus2/authz/internal/repository/company"
	invitationrepo "github.com/tanjed/bus2/authz/internal/repository/invitation"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// Module provides the invitation service, invitations living AUTHZ_INVITE_TTL.
var Module = fx.Module("service.invitation", fx.Provide(
	func(u uow.Transactor, cp cache.Publisher, pub events.Publisher, c idp.Client, cfg config.Config,
		invitations invitationrepo.Repo, members memberrepo.Repo, roles rolerepo.Repo, companies companyrepo.Repo) *Service {
		return New(u, cp, pub, c, cfg.InviteTTL, invitations, members, roles, companies)
	},
))

func New(u uow.Transactor, cp cache.Publisher, pub events.Publisher, c idp.Client, ttl time.Duration,
	invitations invitationrepo.Repo, members memberrepo.Repo, roles rolerepo.Repo, companies companyrepo.Repo) *Service {
	return &Service{uow: u, cache: cp, events: pub, idp: c, ttl: ttl, now: time.Now,
		invitations: invitations, members: members, roles: roles, companies: companies}
}
