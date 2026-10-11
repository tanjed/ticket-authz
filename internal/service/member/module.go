package member

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// Module provides the member service.
var Module = fx.Module("service.member", fx.Provide(New))

func New(u uow.Transactor, cp cache.Publisher, pub events.Publisher, members memberrepo.Repo, roles rolerepo.Repo) *Service {
	return &Service{uow: u, cache: cp, events: pub, members: members, roles: roles}
}
