// Package user manages the roles users hold in their company. Who belongs to a company is
// Company's; this service keeps only role assignments, each user's authorization version, and
// the gateway view of both.
package user

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
	"github.com/tanjed/bus2/authz/internal/service/access"
)

type Service struct {
	uow     uow.Transactor
	cache   cache.Publisher
	events  events.Publisher
	company company.Client
	users   userrepo.Repo
	roles   rolerepo.Repo
}

// ListRoles is every user of the caller's company holding roles.
func (s *Service) ListRoles(ctx context.Context, c access.Caller) ([]UserRoles, error) {
	if _, err := access.CallerPower(ctx, s.users, c); err != nil {
		return nil, err
	}
	return s.users.List(ctx, c.CompanyID)
}

// SetRoles replaces the roles of a user of the caller's company (Company confirms the
// membership). Every role added or taken away must pass the escalation rule, and the company's
// last admin cannot lose the admin role.
func (s *Service) SetRoles(ctx context.Context, c access.Caller, userID string, roleIDs []string) error {
	if err := access.ValidUserID(userID, "user_id"); err != nil {
		return err
	}
	roleIDs = slices.Compact(slices.Sorted(slices.Values(roleIDs)))
	// Asked before the transaction: a slow Company must not hold one open.
	m, err := s.company.GetMembership(ctx, userID)
	if errors.Is(err, apperror.ErrNotFound) || (err == nil && m.CompanyID != c.CompanyID) {
		return apperror.NotFound("member")
	} else if err != nil {
		return err
	}

	var added, removed []string
	var version int64
	err = s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		p, err := access.CallerPower(ctx, s.users, c)
		if err != nil {
			return err
		}
		current, err := s.users.Lock(ctx, c.CompanyID, userID)
		if err != nil {
			return err
		}
		wanted, err := s.roles.Find(ctx, c.CompanyID, roleIDs)
		if err != nil {
			return err
		}
		for _, id := range roleIDs {
			if _, ok := wanted[id]; !ok {
				return apperror.Fail(apperror.KindInvalid, "unknown_role", "unknown role %q", id)
			}
		}
		added, removed = diff(current, roleIDs)
		if len(added) == 0 && len(removed) == 0 {
			return nil
		}
		touched, err := s.roles.Find(ctx, c.CompanyID, append(slices.Clone(added), removed...))
		if err != nil {
			return err
		}
		if !p.CoversAll(touched) {
			return apperror.Escalation()
		}
		if err := s.keepAnAdmin(ctx, c.CompanyID, userID, touched, removed); err != nil {
			return err
		}
		if err := s.users.ReplaceRoles(ctx, c.CompanyID, userID, roleIDs); err != nil {
			return err
		}
		// A new version: the gateway refuses the user's current token until they refresh it.
		version, err = s.users.BumpVersion(ctx, c.CompanyID, userID)
		return err
	})
	if err == nil && version != 0 {
		s.cache.PutUserVersion(ctx, userID, version)
	}
	if err != nil || (len(added) == 0 && len(removed) == 0) {
		return err
	}
	s.events.Publish(ctx, events.MemberRolesChanged, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "user_id": userID, "role_ids": roleIDs, "by": c.UserID,
	})
	return nil
}

// CreateAdminRole gives the company its protected Admin role (every permission, including future
// ones) and makes userID hold it. Idempotent: an existing protected role is reused and the holding
// ensured. It publishes the company as active, the role and the user's new version.
func (s *Service) CreateAdminRole(ctx context.Context, companyID, userID string) (roleID string, err error) {
	if err := validCompany(companyID); err != nil {
		return "", err
	}
	if err := access.ValidUserID(userID, "user_id"); err != nil {
		return "", err
	}
	var version int64
	var view []cache.RoleView
	err = s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		if err := s.roles.LockCompany(ctx, companyID); err != nil {
			return err
		}
		r, err := s.roles.Protected(ctx, companyID)
		if errors.Is(err, apperror.ErrNotFound) {
			r = rolerepo.Role{ID: uuid.NewString(), Name: AdminRoleName, Protected: true, GrantsAll: true}
			if err := s.roles.Create(ctx, companyID, r); err != nil {
				if errors.Is(err, apperror.ErrDuplicate) {
					return apperror.Fail(apperror.KindConflict, "name_taken", "the company already has a role named %s", AdminRoleName)
				}
				return err
			}
		} else if err != nil {
			return err
		}
		roleID = r.ID
		if _, err := s.users.Lock(ctx, companyID, userID); err != nil {
			return err
		}
		if err := s.users.AddRoles(ctx, companyID, userID, []string{roleID}); err != nil {
			return err
		}
		if version, err = s.users.BumpVersion(ctx, companyID, userID); err != nil {
			return err
		}
		view, err = s.roles.View(ctx, roleID)
		return err
	})
	if err != nil {
		return "", err
	}
	s.cache.PutCompany(ctx, companyID, company.StatusActive)
	if len(view) > 0 {
		s.cache.PutRole(ctx, view[0])
	}
	s.cache.PutUserVersion(ctx, userID, version)
	s.events.Publish(ctx, events.MemberRolesChanged, companyID, map[string]any{
		"company_id": companyID, "user_id": userID, "role_ids": []string{roleID},
	})
	return roleID, nil
}

// AssignRoles gives the user these roles of the company, in addition to what they hold. Role ids
// that no longer exist (or belong to another company) are skipped. A new version is published.
func (s *Service) AssignRoles(ctx context.Context, companyID, userID string, roleIDs []string) error {
	if err := validCompany(companyID); err != nil {
		return err
	}
	if err := access.ValidUserID(userID, "user_id"); err != nil {
		return err
	}
	var version int64
	var held []string
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		if _, err := s.users.Lock(ctx, companyID, userID); err != nil {
			return err
		}
		if err := s.users.AddRoles(ctx, companyID, userID, roleIDs); err != nil {
			return err
		}
		var err error
		if held, err = s.users.RoleIDs(ctx, userID); err != nil {
			return err
		}
		version, err = s.users.BumpVersion(ctx, companyID, userID)
		return err
	})
	if err != nil {
		return err
	}
	s.cache.PutUserVersion(ctx, userID, version)
	s.events.Publish(ctx, events.MemberRolesChanged, companyID, map[string]any{
		"company_id": companyID, "user_id": userID, "role_ids": held,
	})
	return nil
}

// CheckAssignable applies the escalation rule for an invitation: every role must belong to the
// company, and the caller's own permissions (read fresh, never from a token) must cover them.
func (s *Service) CheckAssignable(ctx context.Context, companyID, callerUserID string, roleIDs []string) error {
	if err := validCompany(companyID); err != nil {
		return err
	}
	if err := access.ValidUserID(callerUserID, "caller_user_id"); err != nil {
		return err
	}
	roleIDs = slices.Compact(slices.Sorted(slices.Values(roleIDs)))
	p, err := access.CallerPower(ctx, s.users, access.Caller{UserID: callerUserID, CompanyID: companyID})
	if err != nil {
		return err
	}
	found, err := s.roles.Find(ctx, companyID, roleIDs)
	if err != nil {
		return err
	}
	for _, id := range roleIDs {
		if _, ok := found[id]; !ok {
			return apperror.NotFound("role")
		}
	}
	if !p.CoversAll(found) {
		return apperror.Escalation()
	}
	return nil
}

// CanRemoveUser reports whether the user can leave the company: not when they are the only holder
// of the protected Admin role (reason "last_admin").
func (s *Service) CanRemoveUser(ctx context.Context, companyID, userID string) (removable bool, reason string, err error) {
	if err := validCompany(companyID); err != nil {
		return false, "", err
	}
	if err := access.ValidUserID(userID, "user_id"); err != nil {
		return false, "", err
	}
	removable = true
	// On the primary: Company asks right before it removes, and a replica may lag a role change.
	err = s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		admin, err := s.roles.Protected(ctx, companyID)
		if errors.Is(err, apperror.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		holds, err := s.users.Holds(ctx, companyID, admin.ID, userID)
		if err != nil || !holds {
			return err
		}
		others, err := s.users.OtherHolders(ctx, companyID, admin.ID, userID)
		if err != nil {
			return err
		}
		if others == 0 {
			removable, reason = false, "last_admin"
		}
		return nil
	})
	return removable, reason, err
}

// RevokeUser takes every role from the user and gives them a new version, so their token is stale
// at once. Idempotent.
func (s *Service) RevokeUser(ctx context.Context, companyID, userID string) error {
	if err := validCompany(companyID); err != nil {
		return err
	}
	if err := access.ValidUserID(userID, "user_id"); err != nil {
		return err
	}
	var version int64
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		if _, err := s.users.Lock(ctx, companyID, userID); err != nil {
			return err
		}
		if err := s.users.DeleteRoles(ctx, userID); err != nil {
			return err
		}
		var err error
		version, err = s.users.BumpVersion(ctx, companyID, userID)
		return err
	})
	if err != nil {
		return err
	}
	s.cache.PutUserVersion(ctx, userID, version)
	s.events.Publish(ctx, events.MemberRolesChanged, companyID, map[string]any{
		"company_id": companyID, "user_id": userID, "role_ids": []string{}, "revoked": true,
	})
	return nil
}

// Me is the caller's own access, read on the primary inside a unit of work (never from the
// token): the sorted union of their roles' live permissions, or ["*"] when a role grants all,
// and the roles with their landing paths.
func (s *Service) Me(ctx context.Context, c access.Caller) (Me, error) {
	var out Me
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		if _, err := access.CallerPower(ctx, s.users, c); err != nil {
			return err
		}
		ids, err := s.users.RoleIDs(ctx, c.UserID)
		if err != nil {
			return err
		}
		found, err := s.roles.Find(ctx, c.CompanyID, ids)
		if err != nil {
			return err
		}
		views, err := s.roles.View(ctx, ids...)
		if err != nil {
			return err
		}
		set := map[string]bool{}
		for _, v := range views {
			if v.CompanyID != c.CompanyID {
				continue
			}
			for _, k := range v.Permissions {
				set[k] = true
			}
		}
		out = Me{UserID: c.UserID, CompanyID: c.CompanyID, Permissions: []string{}}
		if set[cache.AllPermission] {
			out.Permissions = []string{cache.AllPermission}
		} else {
			out.Permissions = slices.Sorted(maps.Keys(set))
		}
		for _, r := range found {
			out.Roles = append(out.Roles, MeRole{ID: r.ID, Name: r.Name, LandingPath: r.LandingPath})
		}
		slices.SortFunc(out.Roles, func(a, b MeRole) int { return strings.Compare(a.Name, b.Name) })
		return nil
	})
	return out, err
}
