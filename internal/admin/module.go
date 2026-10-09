package admin

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// Module serves AdminService over rbac and registers it on the public listener.
var Module = fx.Module("admin",
	fx.Provide(
		fx.Private,
		fx.Annotate(func(s *rbac.Service) *rbac.Service { return s }, fx.As(new(Backend))),
		New,
	),
	fx.Invoke((*Admin).Register),
)
