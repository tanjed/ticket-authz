package admin

import (
	"context"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service"
)

func (a *Admin) ListInvitations(ctx context.Context, _ *authzv1.ListInvitationsRequest) (*authzv1.ListInvitationsResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	list, err := a.Invitations.List(ctx, c)
	if err != nil {
		return nil, router.Error(a.Log, err)
	}
	out := &authzv1.ListInvitationsResponse{}
	for _, i := range list {
		out.Invitations = append(out.Invitations, InvitationPB(i))
	}
	return out, nil
}

func (a *Admin) CreateInvitation(ctx context.Context, req *authzv1.CreateInvitationRequest) (*authzv1.CreateInvitationResponse, error) {
	c, err := callerFrom(ctx)
	if err != nil {
		return nil, err
	}
	inv, err := a.Invitations.Create(ctx, c, service.InvitationInput{Phone: req.GetPhone(), RoleIDs: req.GetRoleIds()})
	if err != nil {
		return nil, router.Error(a.Log, err)
	}
	return &authzv1.CreateInvitationResponse{Invitation: InvitationPB(inv)}, nil
}
