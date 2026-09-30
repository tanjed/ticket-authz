package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/protobuf/types/known/timestamppb"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/rbac"
)

// Admin implements AdminService: the company admin API behind the gateway.
type Admin struct {
	authzv1.UnimplementedAdminServiceServer
	Svc AdminBackend
	Log *slog.Logger
}

func (a *Admin) ListPermissions(ctx context.Context, _ *authzv1.ListPermissionsRequest) (*authzv1.ListPermissionsResponse, error) {
	if _, err := callerFrom(ctx); err != nil {
		return nil, err
	}
	list, err := a.Svc.Permissions(ctx)
	if err != nil {
		return nil, toStatus(a.Log, err)
	}
	out := &authzv1.ListPermissionsResponse{}
	for _, p := range list {
		out.Permissions = append(out.Permissions, &authzv1.Permission{Key: p.Key, Service: p.Service, Description: p.Description})
	}
	return out, nil
}

func (a *Admin) ListRoles(ctx context.Context, _ *authzv1.ListRolesRequest) (*authzv1.ListRolesResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	roles, err := a.Svc.ListRoles(ctx, c)
	if err != nil {
		return nil, toStatus(a.Log, err)
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
	r, err := a.Svc.GetRole(ctx, c, req.GetId())
	if err != nil {
		return nil, toStatus(a.Log, err)
	}
	return &authzv1.GetRoleResponse{Role: rolePB(r)}, nil
}

func (a *Admin) CreateRole(ctx context.Context, req *authzv1.CreateRoleRequest) (*authzv1.CreateRoleResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	r, err := a.Svc.CreateRole(ctx, c, rbac.RoleInput{Name: req.GetName(), Permissions: req.GetPermissions()})
	if err != nil {
		return nil, toStatus(a.Log, err)
	}
	return &authzv1.CreateRoleResponse{Role: rolePB(r)}, nil
}

func (a *Admin) UpdateRole(ctx context.Context, req *authzv1.UpdateRoleRequest) (*authzv1.UpdateRoleResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	r, err := a.Svc.UpdateRole(ctx, c, req.GetId(), rbac.RoleInput{Name: req.GetName(), Permissions: req.GetPermissions()})
	if err != nil {
		return nil, toStatus(a.Log, err)
	}
	return &authzv1.UpdateRoleResponse{Role: rolePB(r)}, nil
}

func (a *Admin) DeleteRole(ctx context.Context, req *authzv1.DeleteRoleRequest) (*authzv1.DeleteRoleResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.Svc.DeleteRole(ctx, c, req.GetId()); err != nil {
		return nil, toStatus(a.Log, err)
	}
	return &authzv1.DeleteRoleResponse{}, nil
}

func (a *Admin) ListMembers(ctx context.Context, _ *authzv1.ListMembersRequest) (*authzv1.ListMembersResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	members, err := a.Svc.ListMembers(ctx, c)
	if err != nil {
		return nil, toStatus(a.Log, err)
	}
	out := &authzv1.ListMembersResponse{}
	for _, m := range members {
		out.Members = append(out.Members, &authzv1.Member{Sub: m.Sub, RoleIds: m.RoleIDs, CreateTime: timestamppb.New(m.CreatedAt)})
	}
	return out, nil
}

func (a *Admin) SetMemberRoles(ctx context.Context, req *authzv1.SetMemberRolesRequest) (*authzv1.SetMemberRolesResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.Svc.SetMemberRoles(ctx, c, req.GetSub(), req.GetRoleIds()); err != nil {
		return nil, toStatus(a.Log, err)
	}
	return &authzv1.SetMemberRolesResponse{}, nil
}

func (a *Admin) RemoveMember(ctx context.Context, req *authzv1.RemoveMemberRequest) (*authzv1.RemoveMemberResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.Svc.RemoveMember(ctx, c, req.GetSub()); err != nil {
		return nil, toStatus(a.Log, err)
	}
	return &authzv1.RemoveMemberResponse{}, nil
}

func (a *Admin) ListInvitations(ctx context.Context, _ *authzv1.ListInvitationsRequest) (*authzv1.ListInvitationsResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	list, err := a.Svc.ListInvitations(ctx, c)
	if err != nil {
		return nil, toStatus(a.Log, err)
	}
	out := &authzv1.ListInvitationsResponse{}
	for _, i := range list {
		out.Invitations = append(out.Invitations, invitationPB(i))
	}
	return out, nil
}

func (a *Admin) CreateInvitation(ctx context.Context, req *authzv1.CreateInvitationRequest) (*authzv1.CreateInvitationResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := a.Svc.CreateInvitation(ctx, c, rbac.InvitationInput{Phone: req.GetPhone(), RoleIDs: req.GetRoleIds()})
	if err != nil {
		return nil, toStatus(a.Log, err)
	}
	return &authzv1.CreateInvitationResponse{Invitation: invitationPB(inv)}, nil
}
