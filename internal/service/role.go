package service

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/events"
)

// RoleService manages a company's roles under the escalation rule.
type RoleService struct {
	uow       UnitOfWork
	view      GatewayView
	events    events.Publisher
	roles     RoleRepoFactory
	members   MemberRepoFactory
	catalogue CatalogueRepoFactory
}

type roleRepos struct {
	roles     RoleRepo
	members   MemberRepo
	catalogue CatalogueRepo
}

func NewRoleService(uow UnitOfWork, view GatewayView, pub events.Publisher, roles RoleRepoFactory, members MemberRepoFactory, cat CatalogueRepoFactory) *RoleService {
	return &RoleService{uow: uow, view: view, events: pub, roles: roles, members: members, catalogue: cat}
}

func (s *RoleService) bind(q db.Querier) roleRepos {
	return roleRepos{roles: s.roles(q), members: s.members(q), catalogue: s.catalogue(q)}
}

func (s *RoleService) List(ctx context.Context, c Caller) ([]Role, error) {
	var out []Role
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r roleRepos) error {
		if _, err := callerPower(ctx, r.members, c); err != nil {
			return err
		}
		var err error
		out, err = r.roles.List(ctx, c.CompanyID)
		return err
	})
	return out, err
}

func (s *RoleService) Get(ctx context.Context, c Caller, id string) (Role, error) {
	var out Role
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r roleRepos) error {
		if _, err := callerPower(ctx, r.members, c); err != nil {
			return err
		}
		found, err := r.roles.Find(ctx, c.CompanyID, []string{id})
		if err != nil {
			return err
		}
		var ok bool
		if out, ok = found[id]; !ok {
			return notFound("role")
		}
		return nil
	})
	return out, err
}

func (s *RoleService) Create(ctx context.Context, c Caller, in RoleInput) (Role, error) {
	id := uuid.NewString()
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r roleRepos) error {
		p, err := callerPower(ctx, r.members, c)
		if err != nil {
			return err
		}
		if in, err = liveInput(ctx, r.catalogue, in); err != nil {
			return err
		}
		if !p.Covers(Role{Permissions: in.Permissions}) {
			return escalation()
		}
		if err := r.roles.Create(ctx, c.CompanyID, Role{ID: id, Name: in.Name}); err != nil {
			return nameTaken(err)
		}
		return r.roles.SetPermissions(ctx, id, in.Permissions)
	}, func(ctx context.Context, r roleRepos) error {
		return putRole(ctx, s.view, r.roles, c.CompanyID, id)
	})
	if err != nil {
		return Role{}, err
	}
	s.events.Publish(ctx, events.RoleCreated, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "role_id": id, "name": in.Name, "permissions": in.Permissions, "by": c.Sub,
	})
	return s.Get(ctx, c, id)
}

func (s *RoleService) Update(ctx context.Context, c Caller, id string, in RoleInput) (Role, error) {
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r roleRepos) error {
		p, err := callerPower(ctx, r.members, c)
		if err != nil {
			return err
		}
		old, err := lockRole(ctx, r.roles, c.CompanyID, id)
		if err != nil {
			return err
		}
		if old.Protected {
			return fail(KindPrecondition, "protected_role", "the %s role cannot be changed", old.Name)
		}
		if in, err = liveInput(ctx, r.catalogue, in); err != nil {
			return err
		}
		if !p.Covers(old) || !p.Covers(Role{Permissions: in.Permissions}) {
			return escalation()
		}
		if err := r.roles.Rename(ctx, id, in.Name); err != nil {
			return nameTaken(err)
		}
		return r.roles.SetPermissions(ctx, id, in.Permissions)
	}, func(ctx context.Context, r roleRepos) error {
		return putRole(ctx, s.view, r.roles, c.CompanyID, id)
	})
	if err != nil {
		return Role{}, err
	}
	s.events.Publish(ctx, events.RoleUpdated, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "role_id": id, "name": in.Name, "permissions": in.Permissions, "by": c.Sub,
	})
	return s.Get(ctx, c, id)
}

func (s *RoleService) Delete(ctx context.Context, c Caller, id string) error {
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r roleRepos) error {
		p, err := callerPower(ctx, r.members, c)
		if err != nil {
			return err
		}
		old, err := lockRole(ctx, r.roles, c.CompanyID, id)
		if err != nil {
			return err
		}
		if old.Protected {
			return fail(KindPrecondition, "protected_role", "the %s role cannot be deleted", old.Name)
		}
		if !p.Covers(old) {
			return escalation()
		}
		inUse, err := r.roles.Assigned(ctx, id)
		if err != nil {
			return err
		}
		if inUse {
			return fail(KindPrecondition, "role_in_use", "the role is still assigned; unassign it first")
		}
		return r.roles.Delete(ctx, id)
	}, func(ctx context.Context, _ roleRepos) error {
		return s.view.DeleteRole(ctx, c.CompanyID, id)
	})
	if err != nil {
		return err
	}
	s.events.Publish(ctx, events.RoleDeleted, c.CompanyID, map[string]any{"company_id": c.CompanyID, "role_id": id, "by": c.Sub})
	return nil
}

// liveInput normalizes the input and checks every permission is live in the catalogue.
func liveInput(ctx context.Context, cat CatalogueRepo, in RoleInput) (RoleInput, error) {
	in, err := in.normalized()
	if err != nil {
		return in, err
	}
	live, err := cat.LiveKeys(ctx, in.Permissions)
	if err != nil {
		return in, err
	}
	for _, k := range in.Permissions {
		if !slices.Contains(live, k) {
			return in, unknownPermission(k)
		}
	}
	return in, nil
}

// lockRole locks a role of the company; an id that is not a uuid is simply not found.
func lockRole(ctx context.Context, roles RoleRepo, companyID, id string) (Role, error) {
	if uuid.Validate(id) != nil {
		return Role{}, notFound("role")
	}
	r, err := roles.Lock(ctx, companyID, id)
	if errors.Is(err, ErrNotFound) {
		return Role{}, notFound("role")
	}
	return r, err
}

func nameTaken(err error) error {
	if errors.Is(err, ErrDuplicate) {
		return fail(KindConflict, "name_taken", "a role with this name already exists")
	}
	return err
}

// putRole updates one role in the gateway view, deleting it if it no longer exists.
func putRole(ctx context.Context, view GatewayView, roles RoleRepo, companyID, roleID string) error {
	list, err := roles.View(ctx, roleID)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		return view.DeleteRole(ctx, companyID, roleID)
	}
	return view.PutRole(ctx, list[0])
}
