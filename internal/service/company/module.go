package company

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	companyrepo "github.com/tanjed/bus2/authz/internal/repository/company"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// Module provides the company service.
var Module = fx.Module("service.company", fx.Provide(New))

func New(u uow.Transactor, cp cache.Publisher, pub events.Publisher, companies companyrepo.Repo, roles rolerepo.Repo, members memberrepo.Repo) *Service {
	return &Service{uow: u, cache: cp, events: pub, companies: companies, roles: roles, members: members}
}
