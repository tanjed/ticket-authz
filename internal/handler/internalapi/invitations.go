package internalapi

import (
	"context"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/handler/admin"
)

func (s *Internal) GetInvitation(ctx context.Context, req *authzv1.GetInvitationRequest) (*authzv1.GetInvitationResponse, error) {
	inv, err := s.Invitations.Get(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &authzv1.GetInvitationResponse{Invitation: admin.InvitationPB(inv)}, nil
}

func (s *Internal) AcceptInvitation(ctx context.Context, req *authzv1.AcceptInvitationRequest) (*authzv1.AcceptInvitationResponse, error) {
	if err := s.Invitations.Accept(ctx, req.GetId(), req.GetSub()); err != nil {
		return nil, err
	}
	return &authzv1.AcceptInvitationResponse{}, nil
}
