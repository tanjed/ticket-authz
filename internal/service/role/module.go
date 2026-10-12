package role

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// Module provides the role service.
var Module = fx.Module("service.role", fx.Provide(New))

func New(u uow.Transactor, cp cache.Publisher, pub events.Publisher, roles rolerepo.Repo, users userrepo.Repo, cat catalogrepo.Repo) *Service {
	return &Service{uow: u, cache: cp, events: pub, roles: roles, users: users, catalogue: cat}
}
