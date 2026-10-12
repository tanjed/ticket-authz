package internalapi

import (
	"context"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
)

func (s *Internal) CreateAdminRole(ctx context.Context, req *authzv1.CreateAdminRoleRequest) (*authzv1.CreateAdminRoleResponse, error) {
	id, err := s.Users.CreateAdminRole(ctx, req.GetCompanyId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	return &authzv1.CreateAdminRoleResponse{RoleId: id}, nil
}

func (s *Internal) AssignRoles(ctx context.Context, req *authzv1.AssignRolesRequest) (*authzv1.AssignRolesResponse, error) {
	if err := s.Users.AssignRoles(ctx, req.GetCompanyId(), req.GetUserId(), req.GetRoleIds()); err != nil {
		return nil, err
	}
	return &authzv1.AssignRolesResponse{}, nil
}

func (s *Internal) CheckAssignable(ctx context.Context, req *authzv1.CheckAssignableRequest) (*authzv1.CheckAssignableResponse, error) {
	if err := s.Users.CheckAssignable(ctx, req.GetCompanyId(), req.GetCallerUserId(), req.GetRoleIds()); err != nil {
		return nil, err
	}
	return &authzv1.CheckAssignableResponse{}, nil
}

func (s *Internal) CanRemoveUser(ctx context.Context, req *authzv1.CanRemoveUserRequest) (*authzv1.CanRemoveUserResponse, error) {
	removable, reason, err := s.Users.CanRemoveUser(ctx, req.GetCompanyId(), req.GetUserId())
	if err != nil {
		return nil, err
	}
	return &authzv1.CanRemoveUserResponse{Removable: removable, Reason: reason}, nil
}

func (s *Internal) RevokeUser(ctx context.Context, req *authzv1.RevokeUserRequest) (*authzv1.RevokeUserResponse, error) {
	if err := s.Users.RevokeUser(ctx, req.GetCompanyId(), req.GetUserId()); err != nil {
		return nil, err
	}
	return &authzv1.RevokeUserResponse{}, nil
}
