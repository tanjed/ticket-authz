// Package admin serves AdminService, the company admin API behind the gateway. It trusts the
// gateway's X-Bus-* headers, so it is served on the public listener only. Each method reads the
// caller, calls a service and maps the result; the rules live in internal/service.
package admin

import (
	"context"
	"log/slog"

	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service"
)

// The services AdminService calls, each as narrow as its methods here.
type (
	Permissions interface {
		Permissions(ctx context.Context) ([]service.PermissionInfo, error)
	}
	Roles interface {
		List(ctx context.Context, c service.Caller) ([]service.Role, error)
		Get(ctx context.Context, c service.Caller, id string) (service.Role, error)
		Create(ctx context.Context, c service.Caller, in service.RoleInput) (service.Role, error)
		Update(ctx context.Context, c service.Caller, id string, in service.RoleInput) (service.Role, error)
		Delete(ctx context.Context, c service.Caller, id string) error
	}
	Members interface {
		List(ctx context.Context, c service.Caller) ([]service.Member, error)
		SetRoles(ctx context.Context, c service.Caller, sub string, roleIDs []string) error
		Remove(ctx context.Context, c service.Caller, sub string) error
	}
	Invitations interface {
		List(ctx context.Context, c service.Caller) ([]service.Invitation, error)
		Create(ctx context.Context, c service.Caller, in service.InvitationInput) (service.Invitation, error)
	}
)

var (
	_ Permissions                        = (*service.CatalogueService)(nil)
	_ Roles                              = (*service.RoleService)(nil)
	_ Members                            = (*service.MemberService)(nil)
	_ Invitations                        = (*service.InvitationService)(nil)
	_ authzv1connect.AdminServiceHandler = (*Admin)(nil)
)

// Admin implements AdminService.
type Admin struct {
	authzv1connect.UnimplementedAdminServiceHandler
	Permissions Permissions
	Roles       Roles
	Members     Members
	Invitations Invitations
	Log         *slog.Logger
}

func New(perms *service.CatalogueService, roles *service.RoleService, members *service.MemberService, invitations *service.InvitationService, log *slog.Logger) *Admin {
	return &Admin{Permissions: perms, Roles: roles, Members: members, Invitations: invitations, Log: log}
}

// Register serves AdminService on the public listener only: it trusts the gateway's X-Bus-*
// headers.
func (a *Admin) Register(r router.Registrar) {
	r.Public(authzv1connect.NewAdminServiceHandler(a, r.HandlerOptions()...))
}
