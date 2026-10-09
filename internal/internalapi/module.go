package internalapi

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// Module serves InternalService over rbac and registers it on the internal listener.
var Module = fx.Module("internalapi",
	fx.Provide(
		fx.Private,
		fx.Annotate(func(s *rbac.Service) *rbac.Service { return s }, fx.As(new(Backend))),
		New,
	),
	fx.Invoke((*Internal).Register),
)
