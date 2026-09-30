package grpcapi

import (
	"log/slog"

	"go.uber.org/fx"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/rbac"
)

// Module provides the proto service implementations.
var Module = fx.Module("grpcapi", fx.Provide(
	func(svc *rbac.Service, log *slog.Logger) authzv1.AdminServiceServer {
		return &Admin{Svc: svc, Log: log}
	},
	func(svc *rbac.Service, log *slog.Logger) authzv1.InternalServiceServer {
		return &Internal{Svc: svc, Log: log}
	},
))
