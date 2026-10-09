package service

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/events"
)

// CompanyService registers companies, suspends them, and answers the IdP's claims lookup.
type CompanyService struct {
	uow       UnitOfWork
	view      GatewayView
	events    events.Publisher
	companies CompanyRepoFactory
	roles     RoleRepoFactory
	members   MemberRepoFactory
}

type companyRepos struct {
	companies CompanyRepo
	roles     RoleRepo
	members   MemberRepo
}

func NewCompanyService(uow UnitOfWork, view GatewayView, pub events.Publisher, companies CompanyRepoFactory, roles RoleRepoFactory, members MemberRepoFactory) *CompanyService {
	return &CompanyService{uow: uow, view: view, events: pub, companies: companies, roles: roles, members: members}
}

func (s *CompanyService) bind(q db.Querier) companyRepos {
	return companyRepos{companies: s.companies(q), roles: s.roles(q), members: s.members(q)}
}

// Claims resolves a subject's company and roles for a provider login.
func (s *CompanyService) Claims(ctx context.Context, sub string) (Claims, error) {
	var c Claims
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r companyRepos) error {
		m, err := r.members.Membership(ctx, sub)
		if errors.Is(err, ErrNotFound) {
			return fail(KindNotFound, "not_a_member", "subject belongs to no company")
		} else if err != nil {
			return err
		}
		if m.CompanyStatus != StatusActive {
			return fail(KindForbidden, "company_suspended", "company is suspended")
		}
		c = Claims{CompanyID: m.CompanyID, AuthzVersion: m.AuthzVersion}
		c.Roles, err = r.members.RoleRefs(ctx, sub)
		return err
	})
	return c, err
}

// Create registers a company with its protected admin role held by adminSub. Idempotent per
// subject: if adminSub already belongs to a company, that company is returned (created=false).
func (s *CompanyService) Create(ctx context.Context, name, adminSub string) (companyID string, created bool, err error) {
	if name, err = validCompanyName(name); err != nil {
		return "", false, err
	}
	if err := validSubject(adminSub, "admin_sub"); err != nil {
		return "", false, err
	}
	if id, err := s.companyOf(ctx, adminSub); err != nil || id != "" {
		return id, false, err
	}

	companyID, roleID := uuid.NewString(), uuid.NewString()
	var version int64
	err = write(ctx, s.uow, s.bind, func(ctx context.Context, r companyRepos) error {
		if err := r.companies.Create(ctx, companyID, name); err != nil {
			return err
		}
		if err := r.roles.Create(ctx, companyID, Role{ID: roleID, Name: AdminRoleName, Protected: true, GrantsAll: true}); err != nil {
			return err
		}
		var err error
		if version, err = r.members.Create(ctx, adminSub, companyID); err != nil {
			return err
		}
		return r.members.ReplaceRoles(ctx, companyID, adminSub, []string{roleID})
	}, func(ctx context.Context, _ companyRepos) error {
		return errors.Join(
			s.view.PutCompany(ctx, companyID, StatusActive),
			s.view.PutRole(ctx, RoleView{CompanyID: companyID, RoleID: roleID, Permissions: []string{AllPermission}}),
			s.view.PutUserVersion(ctx, adminSub, version),
		)
	})
	if errors.Is(err, ErrDuplicate) {
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
func (s *CompanyService) SetStatus(ctx context.Context, companyID, status string) error {
	if status != StatusActive && status != StatusSuspended {
		return fail(KindInvalid, "invalid_status", "status must be active or suspended")
	}
	if uuid.Validate(companyID) != nil {
		return notFound("company")
	}
	changed := false
	return write(ctx, s.uow, s.bind, func(ctx context.Context, r companyRepos) error {
		var err error
		changed, err = r.companies.SetStatus(ctx, companyID, status)
		if errors.Is(err, ErrNotFound) {
			return notFound("company")
		}
		return err
	}, func(ctx context.Context, _ companyRepos) error {
		if !changed {
			return nil
		}
		return s.view.PutCompany(ctx, companyID, status)
	})
}

func (s *CompanyService) companyOf(ctx context.Context, sub string) (string, error) {
	var id string
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r companyRepos) (err error) {
		id, err = r.members.CompanyOf(ctx, sub)
		return err
	})
	return id, err
}
