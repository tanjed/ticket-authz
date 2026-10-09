package admin

import (
	"context"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service"
)

func (a *Admin) ListRoles(ctx context.Context, _ *authzv1.ListRolesRequest) (*authzv1.ListRolesResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := a.Roles.List(ctx, c)
	if err != nil {
		return nil, router.Error(a.Log, err)
	}
	out := &authzv1.ListRolesResponse{}
	for _, r := range roles {
		out.Roles = append(out.Roles, rolePB(r))
	}
	return out, nil
}

func (a *Admin) GetRole(ctx context.Context, req *authzv1.GetRoleRequest) (*authzv1.GetRoleResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	r, err := a.Roles.Get(ctx, c, req.GetId())
	if err != nil {
		return nil, router.Error(a.Log, err)
	}
	return &authzv1.GetRoleResponse{Role: rolePB(r)}, nil
}

func (a *Admin) CreateRole(ctx context.Context, req *authzv1.CreateRoleRequest) (*authzv1.CreateRoleResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	r, err := a.Roles.Create(ctx, c, service.RoleInput{Name: req.GetName(), Permissions: req.GetPermissions()})
	if err != nil {
		return nil, router.Error(a.Log, err)
	}
	return &authzv1.CreateRoleResponse{Role: rolePB(r)}, nil
}

func (a *Admin) UpdateRole(ctx context.Context, req *authzv1.UpdateRoleRequest) (*authzv1.UpdateRoleResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	r, err := a.Roles.Update(ctx, c, req.GetId(), service.RoleInput{Name: req.GetName(), Permissions: req.GetPermissions()})
	if err != nil {
		return nil, router.Error(a.Log, err)
	}
	return &authzv1.UpdateRoleResponse{Role: rolePB(r)}, nil
}

func (a *Admin) DeleteRole(ctx context.Context, req *authzv1.DeleteRoleRequest) (*authzv1.DeleteRoleResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.Roles.Delete(ctx, c, req.GetId()); err != nil {
		return nil, router.Error(a.Log, err)
	}
	return &authzv1.DeleteRoleResponse{}, nil
}
