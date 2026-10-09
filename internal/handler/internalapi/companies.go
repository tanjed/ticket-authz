package internalapi

import (
	"context"

	"connectrpc.com/connect"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service"
)

func (s *Internal) GetClaims(ctx context.Context, req *authzv1.GetClaimsRequest) (*authzv1.GetClaimsResponse, error) {
	c, err := s.Companies.Claims(ctx, req.GetSub())
	if err != nil {
		return nil, router.Error(s.Log, err)
	}
	out := &authzv1.GetClaimsResponse{CompanyId: c.CompanyID, AuthzVersion: c.AuthzVersion}
	for _, r := range c.Roles {
		out.Roles = append(out.Roles, &authzv1.RoleRef{Id: r.ID, Name: r.Name, Version: int32(r.Version)})
	}
	return out, nil
}

func (s *Internal) CreateCompany(ctx context.Context, req *authzv1.CreateCompanyRequest) (*authzv1.CreateCompanyResponse, error) {
	id, created, err := s.Companies.Create(ctx, req.GetName(), req.GetAdminSub())
	if err != nil {
		return nil, router.Error(s.Log, err)
	}
	return &authzv1.CreateCompanyResponse{CompanyId: id, Created: created}, nil
}

func (s *Internal) SetCompanyStatus(ctx context.Context, req *authzv1.SetCompanyStatusRequest) (*authzv1.SetCompanyStatusResponse, error) {
	var st string
	switch req.GetStatus() {
	case authzv1.CompanyStatus_COMPANY_STATUS_ACTIVE:
		st = service.StatusActive
	case authzv1.CompanyStatus_COMPANY_STATUS_SUSPENDED:
		st = service.StatusSuspended
	default:
		return nil, router.WithReason(connect.CodeInvalidArgument, "invalid_status", "status must be COMPANY_STATUS_ACTIVE or COMPANY_STATUS_SUSPENDED")
	}
	if err := s.Companies.SetStatus(ctx, req.GetCompanyId(), st); err != nil {
		return nil, router.Error(s.Log, err)
	}
	return &authzv1.SetCompanyStatusResponse{}, nil
}
