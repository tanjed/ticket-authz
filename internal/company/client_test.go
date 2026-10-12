package company_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/require"

	companyv1 "github.com/tanjed/bus2/authz/api/gen/bus/company/v1"
	"github.com/tanjed/bus2/authz/api/gen/bus/company/v1/companyv1connect"
	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/company"
)

type fake struct {
	companyv1connect.UnimplementedInternalServiceHandler
}

func (fake) GetMembership(_ context.Context, req *companyv1.GetMembershipRequest) (*companyv1.GetMembershipResponse, error) {
	switch req.GetUserId() {
	case "u1":
		return &companyv1.GetMembershipResponse{CompanyId: "c1", Status: companyv1.CompanyStatus_COMPANY_STATUS_ACTIVE}, nil
	case "pending":
		return &companyv1.GetMembershipResponse{CompanyId: "c2", Status: companyv1.CompanyStatus_COMPANY_STATUS_PENDING_SETUP}, nil
	case "boom":
		return nil, connect.NewError(connect.CodeInternal, errors.New("boom"))
	}
	return nil, connect.NewError(connect.CodeNotFound, errors.New("no company"))
}

func (fake) ListCompanyStatuses(context.Context, *companyv1.ListCompanyStatusesRequest) (*companyv1.ListCompanyStatusesResponse, error) {
	return &companyv1.ListCompanyStatusesResponse{Companies: []*companyv1.CompanyStatusEntry{
		{CompanyId: "c1", Status: companyv1.CompanyStatus_COMPANY_STATUS_ACTIVE},
		{CompanyId: "c2", Status: companyv1.CompanyStatus_COMPANY_STATUS_SUSPENDED},
		{CompanyId: "c3", Status: companyv1.CompanyStatus_COMPANY_STATUS_PENDING_SETUP},
	}}, nil
}

func TestClient(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle(companyv1connect.NewInternalServiceHandler(fake{}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ctx := context.Background()
	c := company.New(srv.URL, nil)

	m, err := c.GetMembership(ctx, "u1")
	require.NoError(t, err)
	require.Equal(t, company.Membership{CompanyID: "c1", Status: company.StatusActive}, m)
	m, err = c.GetMembership(ctx, "pending")
	require.NoError(t, err)
	require.Equal(t, company.StatusPendingSetup, m.Status)

	_, err = c.GetMembership(ctx, "nobody")
	require.ErrorIs(t, err, apperror.ErrNotFound)

	_, err = c.GetMembership(ctx, "boom")
	e, ok := apperror.As(err)
	require.True(t, ok)
	require.Equal(t, apperror.KindUnavailable, e.Kind)

	statuses, err := c.ListCompanyStatuses(ctx)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"c1": "active", "c2": "suspended", "c3": "pending_setup"}, statuses)

	// Unreachable: Unavailable, not a raw network error.
	srv.Close()
	_, err = c.GetMembership(ctx, "u1")
	e, ok = apperror.As(err)
	require.True(t, ok)
	require.Equal(t, apperror.KindUnavailable, e.Kind)
	_, err = c.ListCompanyStatuses(ctx)
	e, ok = apperror.As(err)
	require.True(t, ok)
	require.Equal(t, "unavailable", e.Code)
}
