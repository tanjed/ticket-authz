package company

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	companyrepo "github.com/tanjed/bus2/authz/internal/repository/company"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	"github.com/tanjed/bus2/authz/internal/service/access"
)

// Service registers companies, suspends them, and answers the IdP's claims lookup.
type Service struct {
	uow       uow.Transactor
	cache     cache.Publisher
	events    events.Publisher
	companies companyrepo.Repo
	roles     rolerepo.Repo
	members   memberrepo.Repo
}

// Claims resolves a subject's company and roles for a provider login.
func (s *Service) Claims(ctx context.Context, sub string) (Claims, error) {
	m, err := s.members.Membership(ctx, sub)
	if errors.Is(err, apperror.ErrNotFound) {
		return Claims{}, apperror.Fail(apperror.KindNotFound, "not_a_member", "subject belongs to no company")
	} else if err != nil {
		return Claims{}, err
	}
	if m.CompanyStatus != StatusActive {
		return Claims{}, apperror.Fail(apperror.KindForbidden, "company_suspended", "company is suspended")
	}
	c := Claims{CompanyID: m.CompanyID, AuthzVersion: m.AuthzVersion}
	if c.Roles, err = s.members.RoleRefs(ctx, sub); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// Create registers a company with its protected admin role held by adminSub. Idempotent per
// subject: if adminSub already belongs to a company, that company is returned (created=false).
func (s *Service) Create(ctx context.Context, name, adminSub string) (companyID string, created bool, err error) {
	if name, err = validCompanyName(name); err != nil {
		return "", false, err
	}
	if err := access.ValidSubject(adminSub, "admin_sub"); err != nil {
		return "", false, err
	}
	if id, err := s.companyOf(ctx, adminSub); err != nil || id != "" {
		return id, false, err
	}

	companyID, roleID := uuid.NewString(), uuid.NewString()
	var version int64
	err = s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		if err := s.companies.Create(ctx, companyID, name); err != nil {
			return err
		}
		if err := s.roles.Create(ctx, companyID, rolerepo.Role{ID: roleID, Name: AdminRoleName, Protected: true, GrantsAll: true}); err != nil {
			return err
		}
		var err error
		if version, err = s.members.Create(ctx, adminSub, companyID); err != nil {
			return err
		}
		return s.members.ReplaceRoles(ctx, companyID, adminSub, []string{roleID})
	})
	if err == nil {
		s.cache.PutCompany(ctx, companyID, StatusActive)
		s.cache.PutRole(ctx, cache.RoleView{CompanyID: companyID, RoleID: roleID, Permissions: []string{cache.AllPermission}})
		s.cache.PutUserVersion(ctx, adminSub, version)
	}
	if errors.Is(err, apperror.ErrDuplicate) {
		// A concurrent retry for the same subject won: answer with its company.
		id, err := s.companyOf(ctx, adminSub)
		return id, false, err
	}
	if err != nil {
		return "", false, err
	}
	s.events.Publish(ctx, events.CompanyRegistered, companyID, map[string]any{
		"company_id": companyID, "name": name, "admin_sub": adminSub, "admin_role_id": roleID,
	})
	return companyID, true, nil
}

// SetStatus suspends or reactivates a company. The gateway denies every request of a suspended
// company's users at once, and they can no longer sign in to provider apps.
func (s *Service) SetStatus(ctx context.Context, companyID, status string) error {
	if status != StatusActive && status != StatusSuspended {
		return apperror.Fail(apperror.KindInvalid, "invalid_status", "status must be active or suspended")
	}
	if uuid.Validate(companyID) != nil {
		return apperror.NotFound("company")
	}
	changed := false
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		var err error
		changed, err = s.companies.SetStatus(ctx, companyID, status)
		if errors.Is(err, apperror.ErrNotFound) {
			return apperror.NotFound("company")
		}
		return err
	})
	if err == nil && changed {
		s.cache.PutCompany(ctx, companyID, status)
	}
	return err
}

func (s *Service) companyOf(ctx context.Context, sub string) (string, error) {
	return s.members.CompanyOf(ctx, sub)
}

func validCompanyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n == 0 || n > 100 {
		return "", apperror.Fail(apperror.KindInvalid, "invalid_name", "company name must be 1 to 100 characters")
	}
	return name, nil
}
