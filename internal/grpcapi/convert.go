package grpcapi

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/rbac"
)

func rolePB(r rbac.Role) *authzv1.Role {
	return &authzv1.Role{
		Id: r.ID, Name: r.Name, Protected: r.Protected, GrantsAll: r.GrantsAll, Version: int32(r.Version),
		Permissions: r.Permissions, CreateTime: timestamppb.New(r.CreatedAt), UpdateTime: timestamppb.New(r.UpdatedAt),
	}
}

var invitationStatus = map[string]authzv1.InvitationStatus{
	"pending":  authzv1.InvitationStatus_INVITATION_STATUS_PENDING,
	"accepted": authzv1.InvitationStatus_INVITATION_STATUS_ACCEPTED,
	"expired":  authzv1.InvitationStatus_INVITATION_STATUS_EXPIRED,
}

func invitationPB(i rbac.Invitation) *authzv1.Invitation {
	pb := &authzv1.Invitation{
		Id: i.ID, CompanyId: i.CompanyID, CompanyName: i.CompanyName, Phone: i.Phone, RoleIds: i.RoleIDs,
		InvitedBy: i.InvitedBy, Sub: i.Sub, ExpireTime: timestamppb.New(i.ExpiresAt), CreateTime: timestamppb.New(i.CreatedAt),
		Status: invitationStatus[i.Status],
	}
	if i.AcceptedAt != nil {
		pb.AcceptTime = timestamppb.New(*i.AcceptedAt)
	}
	return pb
}
