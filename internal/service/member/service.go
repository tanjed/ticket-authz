package member

import (
	"context"
	"errors"
	"slices"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	"github.com/tanjed/bus2/authz/internal/service/access"
)

// Service manages who belongs to a company and which roles they hold.
type Service struct {
	uow     uow.Transactor
	cache   cache.Publisher
	events  events.Publisher
	members memberrepo.Repo
	roles   rolerepo.Repo
}

func (s *Service) List(ctx context.Context, c access.Caller) ([]Member, error) {
	if _, err := access.CallerPower(ctx, s.members, c); err != nil {
		return nil, err
	}
	return s.members.List(ctx, c.CompanyID)
}

// SetRoles replaces a member's roles. Every role added or taken away must pass the escalation
// rule, and the company's last admin cannot lose the admin role.
func (s *Service) SetRoles(ctx context.Context, c access.Caller, sub string, roleIDs []string) error {
	roleIDs = slices.Compact(slices.Sorted(slices.Values(roleIDs)))
	var added, removed []string
	var version int64
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		p, err := access.CallerPower(ctx, s.members, c)
		if err != nil {
			return err
		}
		current, err := lockMember(ctx, s.members, c.CompanyID, sub)
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
		if err := s.keepAnAdmin(ctx, c.CompanyID, sub, touched, removed); err != nil {
			return err
		}
		if err := s.members.ReplaceRoles(ctx, c.CompanyID, sub, roleIDs); err != nil {
			return err
		}
		// A new version: the gateway refuses the member's current token until they refresh it.
		version, err = s.members.BumpVersion(ctx, sub)
		return err
	})
	if err == nil && version != 0 {
		s.cache.PutUserVersion(ctx, sub, version)
	}
	if err != nil || (len(added) == 0 && len(removed) == 0) {
		return err
	}
	s.events.Publish(ctx, events.MemberRolesChanged, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "sub": sub, "role_ids": roleIDs, "by": c.Sub,
	})
	return nil
}

// Remove takes a user out of the company (they may then join or create another).
func (s *Service) Remove(ctx context.Context, c access.Caller, sub string) error {
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		p, err := access.CallerPower(ctx, s.members, c)
		if err != nil {
			return err
		}
		current, err := lockMember(ctx, s.members, c.CompanyID, sub)
		if err != nil {
			return err
		}
		held, err := s.roles.Find(ctx, c.CompanyID, current)
		if err != nil {
			return err
		}
		if !p.CoversAll(held) {
			return apperror.Escalation()
		}
		if err := s.keepAnAdmin(ctx, c.CompanyID, sub, held, current); err != nil {
			return err
		}
		return s.members.Delete(ctx, sub)
	})
	if err == nil {
		s.cache.DeleteUser(ctx, sub) // no version: the gateway refuses every token of this subject
	}
	if err != nil {
		return err
	}
	s.events.Publish(ctx, events.MemberRemoved, c.CompanyID, map[string]any{"company_id": c.CompanyID, "sub": sub, "by": c.Sub})
	return nil
}

func lockMember(ctx context.Context, members memberrepo.Repo, companyID, sub string) ([]string, error) {
	ids, err := members.Lock(ctx, companyID, sub)
	if errors.Is(err, apperror.ErrNotFound) {
		return nil, apperror.NotFound("member")
	}
	return ids, err
}
