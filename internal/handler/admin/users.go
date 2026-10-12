package admin

import (
	"context"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
)

func (a *Admin) SetMemberRoles(ctx context.Context, req *authzv1.SetMemberRolesRequest) (*authzv1.SetMemberRolesResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := a.Users.SetRoles(ctx, c, req.GetSub(), req.GetRoleIds()); err != nil {
		return nil, err
	}
	return &authzv1.SetMemberRolesResponse{}, nil
}

func (a *Admin) ListUserRoles(ctx context.Context, _ *authzv1.ListUserRolesRequest) (*authzv1.ListUserRolesResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	users, err := a.Users.ListRoles(ctx, c)
	if err != nil {
		return nil, err
	}
	out := &authzv1.ListUserRolesResponse{}
	for _, u := range users {
		out.Users = append(out.Users, &authzv1.UserRoles{UserId: u.UserID, RoleIds: u.RoleIDs})
	}
	return out, nil
}

func (a *Admin) GetMe(ctx context.Context, _ *authzv1.GetMeRequest) (*authzv1.GetMeResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	me, err := a.Users.Me(ctx, c)
	if err != nil {
		return nil, err
	}
	out := &authzv1.GetMeResponse{UserId: me.UserID, CompanyId: me.CompanyID, Permissions: me.Permissions}
	for _, r := range me.Roles {
		out.Roles = append(out.Roles, &authzv1.MeRole{Id: r.ID, Name: r.Name, LandingPath: r.LandingPath})
	}
	return out, nil
}
