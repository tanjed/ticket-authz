// Package admin serves AdminService, the company admin API behind the gateway. It trusts the
// gateway's X-Bus-* headers, so it is served on the public listener only. Each method reads the
// caller, calls a service and maps the result; the rules live in internal/service.
package admin

import (
	"context"

	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/service/access"
	"github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/invitation"
	"github.com/tanjed/bus2/authz/internal/service/member"
	"github.com/tanjed/bus2/authz/internal/service/role"
)

// The services AdminService calls, each as narrow as its methods here.
type (
	Permissions interface {
		Permissions(ctx context.Context) ([]catalogue.Permission, error)
	}
	Roles interface {
		List(ctx context.Context, c access.Caller) ([]role.Role, error)
		Get(ctx context.Context, c access.Caller, id string) (role.Role, error)
		Create(ctx context.Context, c access.Caller, in role.Input) (role.Role, error)
		Update(ctx context.Context, c access.Caller, id string, in role.Input) (role.Role, error)
		Delete(ctx context.Context, c access.Caller, id string) error
	}
	Members interface {
		List(ctx context.Context, c access.Caller) ([]member.Member, error)
		SetRoles(ctx context.Context, c access.Caller, sub string, roleIDs []string) error
		Remove(ctx context.Context, c access.Caller, sub string) error
	}
	Invitations interface {
		List(ctx context.Context, c access.Caller) ([]invitation.Invitation, error)
		Create(ctx context.Context, c access.Caller, in invitation.Input) (invitation.Invitation, error)
	}
)

var (
	_ Permissions                        = (*catalogue.Service)(nil)
	_ Roles                              = (*role.Service)(nil)
	_ Members                            = (*member.Service)(nil)
	_ Invitations                        = (*invitation.Service)(nil)
	_ authzv1connect.AdminServiceHandler = (*Admin)(nil)
)

// Admin implements AdminService.
type Admin struct {
	authzv1connect.UnimplementedAdminServiceHandler
	Permissions Permissions
	Roles       Roles
	Members     Members
	Invitations Invitations
}
