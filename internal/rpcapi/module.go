package rpcapi

import (
	"go.uber.org/fx"

	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/bundle"
	"github.com/tanjed/bus2/authz/internal/rbac"
)

// Module binds the domain to the backends it needs, and provides the implementations as the
// generated service interfaces (consumers never see the concrete types).
var Module = fx.Module("rpcapi", fx.Provide(
	fx.Annotate(func(s *rbac.Service) *rbac.Service { return s }, fx.As(new(AdminBackend)), fx.As(new(InternalBackend))),
	fx.Annotate(NewAdmin, fx.As(new(authzv1connect.AdminServiceHandler))),
	fx.Annotate(func(s *bundle.Server) *bundle.Server { return s }, fx.As(new(BundleBackend))),
	fx.Annotate(NewInternal, fx.As(new(authzv1connect.InternalServiceHandler))),
	fx.Annotate(NewBundle, fx.As(new(authzv1connect.BundleServiceHandler))),
	fx.Annotate(NewHealth, fx.As(new(authzv1connect.HealthServiceHandler))),
))
