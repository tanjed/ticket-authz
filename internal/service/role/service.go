package role

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	"github.com/tanjed/bus2/authz/internal/service/access"
)

// Service manages a company's roles under the escalation rule.
type Service struct {
	uow       uow.Transactor
	cache     cache.Publisher
	events    events.Publisher
	roles     rolerepo.Repo
	members   memberrepo.Repo
	catalogue catalogrepo.Repo
}

func (s *Service) List(ctx context.Context, c access.Caller) ([]Role, error) {
	if _, err := access.CallerPower(ctx, s.members, c); err != nil {
		return nil, err
	}
	return s.roles.List(ctx, c.CompanyID)
}

func (s *Service) Get(ctx context.Context, c access.Caller, id string) (Role, error) {
	if _, err := access.CallerPower(ctx, s.members, c); err != nil {
		return Role{}, err
	}
	found, err := s.roles.Find(ctx, c.CompanyID, []string{id})
	if err != nil {
		return Role{}, err
	}
	r, ok := found[id]
	if !ok {
		return Role{}, apperror.NotFound("role")
	}
	return r, nil
}

func (s *Service) Create(ctx context.Context, c access.Caller, in Input) (Role, error) {
	id := uuid.NewString()
	var view []cache.RoleView
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		p, err := access.CallerPower(ctx, s.members, c)
		if err != nil {
			return err
		}
		if in, err = liveInput(ctx, s.catalogue, in); err != nil {
			return err
		}
		if !p.Covers(Role{Permissions: in.Permissions}) {
			return apperror.Escalation()
		}
		if err := s.roles.Create(ctx, c.CompanyID, Role{ID: id, Name: in.Name}); err != nil {
			return nameTaken(err)
		}
		if err := s.roles.SetPermissions(ctx, id, in.Permissions); err != nil {
			return err
		}
		view, err = s.roles.View(ctx, id)
		return err
	})
	if err == nil {
		s.publishRole(ctx, c.CompanyID, id, view)
	}
	if err != nil {
		return Role{}, err
	}
	s.events.Publish(ctx, events.RoleCreated, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "role_id": id, "name": in.Name, "permissions": in.Permissions, "by": c.Sub,
	})
	return s.Get(ctx, c, id)
}

func (s *Service) Update(ctx context.Context, c access.Caller, id string, in Input) (Role, error) {
	var view []cache.RoleView
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		p, err := access.CallerPower(ctx, s.members, c)
		if err != nil {
			return err
		}
		old, err := lockRole(ctx, s.roles, c.CompanyID, id)
		if err != nil {
			return err
		}
		if old.Protected {
			return apperror.Fail(apperror.KindPrecondition, "protected_role", "the %s role cannot be changed", old.Name)
		}
		if in, err = liveInput(ctx, s.catalogue, in); err != nil {
			return err
		}
		if !p.Covers(old) || !p.Covers(Role{Permissions: in.Permissions}) {
			return apperror.Escalation()
		}
		if err := s.roles.Rename(ctx, id, in.Name); err != nil {
			return nameTaken(err)
		}
		if err := s.roles.SetPermissions(ctx, id, in.Permissions); err != nil {
			return err
		}
		view, err = s.roles.View(ctx, id)
		return err
	})
	if err == nil {
		s.publishRole(ctx, c.CompanyID, id, view)
	}
	if err != nil {
		return Role{}, err
	}
	s.events.Publish(ctx, events.RoleUpdated, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "role_id": id, "name": in.Name, "permissions": in.Permissions, "by": c.Sub,
	})
	return s.Get(ctx, c, id)
}

func (s *Service) Delete(ctx context.Context, c access.Caller, id string) error {
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		p, err := access.CallerPower(ctx, s.members, c)
		if err != nil {
			return err
		}
		old, err := lockRole(ctx, s.roles, c.CompanyID, id)
		if err != nil {
			return err
		}
		if old.Protected {
			return apperror.Fail(apperror.KindPrecondition, "protected_role", "the %s role cannot be deleted", old.Name)
		}
		if !p.Covers(old) {
			return apperror.Escalation()
		}
		inUse, err := s.roles.Assigned(ctx, id)
		if err != nil {
			return err
		}
		if inUse {
			return apperror.Fail(apperror.KindPrecondition, "role_in_use", "the role is still assigned; unassign it first")
		}
		return s.roles.Delete(ctx, id)
	})
	if err == nil {
		s.cache.DeleteRole(ctx, c.CompanyID, id)
	}
	if err != nil {
		return err
	}
	s.events.Publish(ctx, events.RoleDeleted, c.CompanyID, map[string]any{"company_id": c.CompanyID, "role_id": id, "by": c.Sub})
	return nil
}

// liveInput normalizes the input and checks every permission is live in the catalogue.
func liveInput(ctx context.Context, cat catalogrepo.Repo, in Input) (Input, error) {
	in, err := normalized(in)
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
func lockRole(ctx context.Context, roles rolerepo.Repo, companyID, id string) (Role, error) {
	if uuid.Validate(id) != nil {
		return Role{}, apperror.NotFound("role")
	}
	r, err := roles.Lock(ctx, companyID, id)
	if errors.Is(err, apperror.ErrNotFound) {
		return Role{}, apperror.NotFound("role")
	}
	return r, err
}

func nameTaken(err error) error {
	if errors.Is(err, apperror.ErrDuplicate) {
		return apperror.Fail(apperror.KindConflict, "name_taken", "a role with this name already exists")
	}
	return err
}

// publishRole publishes a role's live permissions, read in its write's transaction (or deletes its
// key if it no longer exists).
func (s *Service) publishRole(ctx context.Context, companyID, roleID string, view []cache.RoleView) {
	if len(view) == 0 {
		s.cache.DeleteRole(ctx, companyID, roleID)
		return
	}
	s.cache.PutRole(ctx, view[0])
}
