package internalapi

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/router"
	catalogsvc "github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/company"
	"github.com/tanjed/bus2/authz/internal/service/user"
)

// Module binds the services to the narrow interfaces InternalService declares, and serves it on
// the internal listener only.
var Module = fx.Module("internalapi",
	fx.Provide(
		fx.Private,
		func(s *catalogsvc.Service) Catalogue { return s },
		func(s *company.Service) Companies { return s },
		func(s *user.Service) Users { return s },
		fx.Annotate(New, fx.As(new(authzv1connect.InternalServiceHandler))),
	),
	router.Internal(authzv1connect.NewInternalServiceHandler),
)

func New(cat Catalogue, companies Companies, users Users) *Internal {
	return &Internal{Catalogue: cat, Companies: companies, Users: users}
}
