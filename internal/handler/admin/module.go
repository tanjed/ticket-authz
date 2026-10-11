package admin

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/invitation"
	"github.com/tanjed/bus2/authz/internal/service/member"
	"github.com/tanjed/bus2/authz/internal/service/role"
)

// Module binds the services to the narrow interfaces AdminService declares, and serves it on the
// public listener only (it trusts the gateway's X-Bus-* headers).
var Module = fx.Module("admin",
	fx.Provide(
		fx.Private,
		func(s *catalogue.Service) Permissions { return s },
		func(s *role.Service) Roles { return s },
		func(s *member.Service) Members { return s },
		func(s *invitation.Service) Invitations { return s },
		fx.Annotate(New, fx.As(new(authzv1connect.AdminServiceHandler))),
	),
	router.Public(authzv1connect.NewAdminServiceHandler),
)

func New(perms Permissions, roles Roles, members Members, invitations Invitations) *Admin {
	return &Admin{Permissions: perms, Roles: roles, Members: members, Invitations: invitations}
}
