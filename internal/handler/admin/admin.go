// Package admin serves AdminService, the company admin API behind the gateway. It trusts the
// gateway's X-Bus-* headers, so it is served on the public listener only. Each method reads the
// caller, calls a service and maps the result; the rules live in internal/service.
package admin

import (
	"context"

	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/service/access"
	"github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/role"
	"github.com/tanjed/bus2/authz/internal/service/user"
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
	Users interface {
		ListRoles(ctx context.Context, c access.Caller) ([]user.UserRoles, error)
		SetRoles(ctx context.Context, c access.Caller, userID string, roleIDs []string) error
		Me(ctx context.Context, c access.Caller) (user.Me, error)
	}
)

var (
	_ Permissions                        = (*catalogue.Service)(nil)
	_ Roles                              = (*role.Service)(nil)
	_ Users                              = (*user.Service)(nil)
	_ authzv1connect.AdminServiceHandler = (*Admin)(nil)
)

// Admin implements AdminService.
type Admin struct {
	authzv1connect.UnimplementedAdminServiceHandler
	Permissions Permissions
	Roles       Roles
	Users       Users
}
