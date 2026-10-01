package rpcapi

import (
	"context"
	"log/slog"

	"connectrpc.com/connect"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/catalogue"
)

// Internal implements InternalService: seed Jobs, the IdP and platform operations.
type Internal struct {
	authzv1connect.UnimplementedInternalServiceHandler
	Svc InternalBackend
	Log *slog.Logger
}

func (s *Internal) ApplyManifest(ctx context.Context, req *authzv1.ApplyManifestRequest) (*authzv1.ApplyManifestResponse, error) {
	m := catalogue.Manifest{}
	for _, p := range req.GetPermissions() {
		m.Permissions = append(m.Permissions, catalogue.Permission{Key: p.GetKey(), Description: p.GetDescription(), Consumer: p.GetConsumer()})
	}
	for _, r := range req.GetRoutes() {
		m.Routes = append(m.Routes, catalogue.Route{Name: r.GetName(), Permission: r.GetPermission(), Public: r.GetPublic()})
	}
	res, err := s.Svc.ApplyManifest(ctx, req.GetService(), m)
	if err != nil {
		return nil, toError(s.Log, err)
	}
	return &authzv1.ApplyManifestResponse{
		Service: res.Service, Permissions: int32(res.Permissions), Routes: int32(res.Routes), Changed: res.Changed,
	}, nil
}

func (s *Internal) GetClaims(ctx context.Context, req *authzv1.GetClaimsRequest) (*authzv1.GetClaimsResponse, error) {
	c, err := s.Svc.Claims(ctx, req.GetSub())
	if err != nil {
		return nil, toError(s.Log, err)
	}
	out := &authzv1.GetClaimsResponse{CompanyId: c.CompanyID}
	for _, r := range c.Roles {
		out.Roles = append(out.Roles, &authzv1.RoleRef{Id: r.ID, Name: r.Name, Version: int32(r.Version)})
	}
	return out, nil
}

func (s *Internal) CreateCompany(ctx context.Context, req *authzv1.CreateCompanyRequest) (*authzv1.CreateCompanyResponse, error) {
	id, created, err := s.Svc.CreateCompany(ctx, req.GetName(), req.GetAdminSub())
	if err != nil {
		return nil, toError(s.Log, err)
	}
	return &authzv1.CreateCompanyResponse{CompanyId: id, Created: created}, nil
}

func (s *Internal) SetCompanyStatus(ctx context.Context, req *authzv1.SetCompanyStatusRequest) (*authzv1.SetCompanyStatusResponse, error) {
	var st string
	switch req.GetStatus() {
	case authzv1.CompanyStatus_COMPANY_STATUS_ACTIVE:
		st = "active"
	case authzv1.CompanyStatus_COMPANY_STATUS_SUSPENDED:
		st = "suspended"
	default:
		return nil, withReason(connect.CodeInvalidArgument, "invalid_status", "status must be COMPANY_STATUS_ACTIVE or COMPANY_STATUS_SUSPENDED")
	}
	if err := s.Svc.SetCompanyStatus(ctx, req.GetCompanyId(), st); err != nil {
		return nil, toError(s.Log, err)
	}
	return &authzv1.SetCompanyStatusResponse{}, nil
}

func (s *Internal) GetInvitation(ctx context.Context, req *authzv1.GetInvitationRequest) (*authzv1.GetInvitationResponse, error) {
	inv, err := s.Svc.GetInvitation(ctx, req.GetId())
	if err != nil {
		return nil, toError(s.Log, err)
	}
	return &authzv1.GetInvitationResponse{Invitation: invitationPB(inv)}, nil
}

func (s *Internal) AcceptInvitation(ctx context.Context, req *authzv1.AcceptInvitationRequest) (*authzv1.AcceptInvitationResponse, error) {
	if err := s.Svc.AcceptInvitation(ctx, req.GetId(), req.GetSub()); err != nil {
		return nil, toError(s.Log, err)
	}
	return &authzv1.AcceptInvitationResponse{}, nil
}
