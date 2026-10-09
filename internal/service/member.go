package service

import (
	"context"
	"errors"
	"slices"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/events"
)

// MemberService manages who belongs to a company and which roles they hold.
type MemberService struct {
	uow     UnitOfWork
	view    GatewayView
	events  events.Publisher
	members MemberRepoFactory
	roles   RoleRepoFactory
}

type memberRepos struct {
	members MemberRepo
	roles   RoleRepo
}

func NewMemberService(uow UnitOfWork, view GatewayView, pub events.Publisher, members MemberRepoFactory, roles RoleRepoFactory) *MemberService {
	return &MemberService{uow: uow, view: view, events: pub, members: members, roles: roles}
}

func (s *MemberService) bind(q db.Querier) memberRepos {
	return memberRepos{members: s.members(q), roles: s.roles(q)}
}

func (s *MemberService) List(ctx context.Context, c Caller) ([]Member, error) {
	var out []Member
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r memberRepos) error {
		if _, err := callerPower(ctx, r.members, c); err != nil {
			return err
		}
		var err error
		out, err = r.members.List(ctx, c.CompanyID)
		return err
	})
	return out, err
}

// SetRoles replaces a member's roles. Every role added or taken away must pass the escalation
// rule, and the company's last admin cannot lose the admin role.
func (s *MemberService) SetRoles(ctx context.Context, c Caller, sub string, roleIDs []string) error {
	roleIDs = slices.Compact(slices.Sorted(slices.Values(roleIDs)))
	var added, removed []string
	var version int64
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r memberRepos) error {
		p, err := callerPower(ctx, r.members, c)
		if err != nil {
			return err
		}
		current, err := lockMember(ctx, r.members, c.CompanyID, sub)
		if err != nil {
			return err
		}
		wanted, err := r.roles.Find(ctx, c.CompanyID, roleIDs)
		if err != nil {
			return err
		}
		for _, id := range roleIDs {
			if _, ok := wanted[id]; !ok {
				return fail(KindInvalid, "unknown_role", "unknown role %q", id)
			}
		}
		added, removed = diff(current, roleIDs)
		if len(added) == 0 && len(removed) == 0 {
			return nil
		}
		touched, err := r.roles.Find(ctx, c.CompanyID, append(slices.Clone(added), removed...))
		if err != nil {
			return err
		}
		if !p.coversAll(touched) {
			return escalation()
		}
		if err := keepAnAdmin(ctx, r, c.CompanyID, sub, touched, removed); err != nil {
			return err
		}
		if err := r.members.ReplaceRoles(ctx, c.CompanyID, sub, roleIDs); err != nil {
			return err
		}
		// A new version: the gateway refuses the member's current token until they refresh it.
		version, err = r.members.BumpVersion(ctx, sub)
		return err
	}, func(ctx context.Context, _ memberRepos) error {
		if version == 0 {
			return nil
		}
		return s.view.PutUserVersion(ctx, sub, version)
	})
	if err != nil || (len(added) == 0 && len(removed) == 0) {
		return err
	}
	s.events.Publish(ctx, events.MemberRolesChanged, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "sub": sub, "role_ids": roleIDs, "by": c.Sub,
	})
	return nil
}

// Remove takes a user out of the company (they may then join or create another).
func (s *MemberService) Remove(ctx context.Context, c Caller, sub string) error {
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r memberRepos) error {
		p, err := callerPower(ctx, r.members, c)
		if err != nil {
			return err
		}
		current, err := lockMember(ctx, r.members, c.CompanyID, sub)
		if err != nil {
			return err
		}
		held, err := r.roles.Find(ctx, c.CompanyID, current)
		if err != nil {
			return err
		}
		if !p.coversAll(held) {
			return escalation()
		}
		if err := keepAnAdmin(ctx, r, c.CompanyID, sub, held, current); err != nil {
			return err
		}
		return r.members.Delete(ctx, sub)
	}, func(ctx context.Context, _ memberRepos) error {
		// No version: the gateway refuses every token of this subject.
		return s.view.DeleteUser(ctx, sub)
	})
	if err != nil {
		return err
	}
	s.events.Publish(ctx, events.MemberRemoved, c.CompanyID, map[string]any{"company_id": c.CompanyID, "sub": sub, "by": c.Sub})
	return nil
}

func lockMember(ctx context.Context, members MemberRepo, companyID, sub string) ([]string, error) {
	ids, err := members.Lock(ctx, companyID, sub)
	if errors.Is(err, ErrNotFound) {
		return nil, notFound("member")
	}
	return ids, err
}

// diff is what going from current to wanted adds and removes.
func diff(current, wanted []string) (added, removed []string) {
	for _, id := range wanted {
		if !slices.Contains(current, id) {
			added = append(added, id)
		}
	}
	for _, id := range current {
		if !slices.Contains(wanted, id) {
			removed = append(removed, id)
		}
	}
	return added, removed
}

// keepAnAdmin refuses to take the protected role from its last holder. The role is locked first,
// so two concurrent removals cannot both see "another holder".
func keepAnAdmin(ctx context.Context, r memberRepos, companyID, sub string, roles map[string]Role, removed []string) error {
	for _, id := range removed {
		if !roles[id].Protected {
			continue
		}
		if _, err := r.roles.Lock(ctx, companyID, id); err != nil {
			return err
		}
		others, err := r.members.OtherHolders(ctx, companyID, id, sub)
		if err != nil {
			return err
		}
		if others == 0 {
			return fail(KindPrecondition, "last_admin", "the company must keep at least one %s", roles[id].Name)
		}
	}
	return nil
}
