package company

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// Module provides the company service.
var Module = fx.Module("service.company", fx.Provide(New))

func New(u uow.Transactor, cp cache.Publisher, co company.Client, users userrepo.Repo) *Service {
	return &Service{uow: u, cache: cp, company: co, users: users}
}
