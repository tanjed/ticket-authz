package admin

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/router"
)

func (a *Admin) ListMembers(ctx context.Context, _ *authzv1.ListMembersRequest) (*authzv1.ListMembersResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	members, err := a.Members.List(ctx, c)
	if err != nil {
		return nil, router.Error(a.Log, err)
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
	if err := a.Members.SetRoles(ctx, c, req.GetSub(), req.GetRoleIds()); err != nil {
		return nil, router.Error(a.Log, err)
	}
	return &authzv1.SetMemberRolesResponse{}, nil
}

func (a *Admin) RemoveMember(ctx context.Context, req *authzv1.RemoveMemberRequest) (*authzv1.RemoveMemberResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.Members.Remove(ctx, c, req.GetSub()); err != nil {
		return nil, router.Error(a.Log, err)
	}
	return &authzv1.RemoveMemberResponse{}, nil
}
