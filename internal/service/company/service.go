// Package company answers the IdP's claims lookup and publishes company statuses. The company
// itself (profile, status, who belongs to it) is Company's service; Authz asks it.
package company

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// Statuses a caller may set (pending_setup is Company's alone and is never published).
const (
	StatusActive    = company.StatusActive
	StatusSuspended = company.StatusSuspended
)

// RoleRef is a role as it appears in the token.
type RoleRef = userrepo.RoleRef

// Claims is what the IdP puts in a provider's access token. AuthzVersion is the user's
// authorization version: the gateway refuses the token once the view holds another.
type Claims struct {
	CompanyID    string    `json:"company_id"`
	Roles        []RoleRef `json:"roles"`
	AuthzVersion int64     `json:"authz_version"`
}

type Service struct {
	uow     uow.Transactor
	cache   cache.Publisher
	company company.Client
	users   userrepo.Repo
}

// Claims resolves a user's company (from Company) and roles for a provider login or refresh.
// Company unreachable is UNAVAILABLE: no token is better than one without a company.
func (s *Service) Claims(ctx context.Context, userID string) (Claims, error) {
	m, err := s.company.GetMembership(ctx, userID)
	if errors.Is(err, apperror.ErrNotFound) {
		return Claims{}, apperror.Fail(apperror.KindNotFound, "not_a_member", "user belongs to no company")
	} else if err != nil {
		return Claims{}, err
	}
	if m.Status != company.StatusActive {
		return Claims{}, apperror.Fail(apperror.KindForbidden, "company_suspended", "company is %s", orUnknown(m.Status))
	}
	c := Claims{CompanyID: m.CompanyID}
	// On the primary: a login right after signup or an accepted invitation must find the roles
	// that call just wrote, whatever the replica lag.
	err = s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		var err error
		if c.Roles, err = s.users.RoleRefs(ctx, userID, m.CompanyID); err != nil {
			return err
		}
		c.AuthzVersion, err = s.users.Version(ctx, userID)
		return err
	})
	return c, err
}

// SetStatus publishes a company's status to the gateway view. Company owns the status and has
// already committed it; Authz keeps nothing. A suspended company's users are denied at once.
func (s *Service) SetStatus(ctx context.Context, companyID, status string) error {
	if status != StatusActive && status != StatusSuspended {
		return apperror.Fail(apperror.KindInvalid, "invalid_status", "status must be active or suspended")
	}
	if uuid.Validate(companyID) != nil {
		return apperror.NotFound("company")
	}
	s.cache.PutCompany(ctx, companyID, status)
	return nil
}

func orUnknown(status string) string {
	if status == "" {
		return "in an unknown state"
	}
	return status
}
