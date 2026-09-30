package grpcapi

import (
	"go.uber.org/fx"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/rbac"
)

// Module binds the domain to the backends it needs, and provides the implementations as the
// generated service interfaces (consumers never see the concrete types).
var Module = fx.Module("grpcapi", fx.Provide(
	fx.Annotate(func(s *rbac.Service) *rbac.Service { return s }, fx.As(new(AdminBackend)), fx.As(new(InternalBackend))),
	fx.Annotate(NewAdmin, fx.As(new(authzv1.AdminServiceServer))),
	fx.Annotate(NewInternal, fx.As(new(authzv1.InternalServiceServer))),
))
