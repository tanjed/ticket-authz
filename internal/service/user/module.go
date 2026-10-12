package user

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// Module provides the user service.
var Module = fx.Module("service.user", fx.Provide(New))

func New(u uow.Transactor, cp cache.Publisher, pub events.Publisher, co company.Client, users userrepo.Repo, roles rolerepo.Repo) *Service {
	return &Service{uow: u, cache: cp, events: pub, company: co, users: users, roles: roles}
}
