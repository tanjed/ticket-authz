// Package company calls the Company service's internal API (../Company): who belongs to which
// company, and each company's status. Authz keeps no copy of either; it asks at login (claims),
// when a caller assigns roles, and at boot (the resync). The wire contract is the vendored subset
// proto/bus/company/v1/internal.proto.
package company

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	companyv1 "github.com/tanjed/bus2/authz/api/gen/bus/company/v1"
	"github.com/tanjed/bus2/authz/api/gen/bus/company/v1/companyv1connect"
	"github.com/tanjed/bus2/authz/internal/apperror"
)

// Company statuses, as Company reports them.
const (
	StatusPendingSetup = "pending_setup"
	StatusActive       = "active"
	StatusSuspended    = "suspended"
)

// Membership is the company a user belongs to and its status.
type Membership struct {
	CompanyID string
	Status    string
}

// Client is what Authz needs from Company.
type Client interface {
	// GetMembership returns apperror.ErrNotFound when the user belongs to no company. Any other
	// failure (Company unreachable, an error reply) is an apperror Unavailable.
	GetMembership(ctx context.Context, userID string) (Membership, error)
	// ListCompanyStatuses is every company's status, by company id. Unavailable on failure.
	ListCompanyStatuses(ctx context.Context) (map[string]string, error)
}

var _ Client = (*Connect)(nil)

// Connect is the Client over Connect (HTTP/1.1 or h2c; Company's Vanguard serves it).
type Connect struct {
	rpc companyv1connect.InternalServiceClient
	log *slog.Logger
}

// New: each call is a client span and carries the traceparent (otelhttp).
func New(baseURL string, log *slog.Logger) *Connect {
	if log == nil {
		log = slog.Default()
	}
	hc := &http.Client{Timeout: 5 * time.Second, Transport: otelhttp.NewTransport(http.DefaultTransport)}
	return &Connect{rpc: companyv1connect.NewInternalServiceClient(hc, baseURL), log: log}
}

func (c *Connect) GetMembership(ctx context.Context, userID string) (Membership, error) {
	res, err := c.rpc.GetMembership(ctx, &companyv1.GetMembershipRequest{UserId: userID})
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			return Membership{}, apperror.ErrNotFound
		}
		return Membership{}, c.unavailable(ctx, "GetMembership", err)
	}
	return Membership{CompanyID: res.GetCompanyId(), Status: statusName(res.GetStatus())}, nil
}

func (c *Connect) ListCompanyStatuses(ctx context.Context) (map[string]string, error) {
	res, err := c.rpc.ListCompanyStatuses(ctx, &companyv1.ListCompanyStatusesRequest{})
	if err != nil {
		return nil, c.unavailable(ctx, "ListCompanyStatuses", err)
	}
	out := make(map[string]string, len(res.GetCompanies()))
	for _, e := range res.GetCompanies() {
		out[e.GetCompanyId()] = statusName(e.GetStatus())
	}
	return out, nil
}

func statusName(s companyv1.CompanyStatus) string {
	switch s {
	case companyv1.CompanyStatus_COMPANY_STATUS_PENDING_SETUP:
		return StatusPendingSetup
	case companyv1.CompanyStatus_COMPANY_STATUS_ACTIVE:
		return StatusActive
	case companyv1.CompanyStatus_COMPANY_STATUS_SUSPENDED:
		return StatusSuspended
	default:
		return ""
	}
}

// unavailable: a transport failure or any reply that is not an answer. The cause is logged, not
// shown to callers (a domain error carries only its code and message).
func (c *Connect) unavailable(ctx context.Context, rpc string, err error) error {
	c.log.ErrorContext(ctx, "company call failed", "rpc", rpc, "err", err)
	return apperror.Fail(apperror.KindUnavailable, "unavailable", "company service unavailable")
}
