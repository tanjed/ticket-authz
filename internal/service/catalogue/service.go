package catalogue

import (
	"context"
	"errors"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// Service applies service manifests (permissions and routes) and lists the catalogue.
type Service struct {
	uow       uow.Transactor
	cache     cache.Publisher
	catalogue catalogrepo.Repo
	roles     rolerepo.Repo
}

// ApplyManifest replaces a service's permissions and routes. Anything the service no longer lists
// is deprecated, never deleted (role links survive a rollback); listing it again restores it.
func (s *Service) ApplyManifest(ctx context.Context, service string, m catalogue.Manifest) (Result, error) {
	if !catalogue.ValidService(service) {
		return Result{}, apperror.Fail(apperror.KindInvalid, "invalid_service", "invalid service name %q", service)
	}
	if err := m.Validate(); err != nil {
		return Result{}, apperror.Fail(apperror.KindInvalid, "invalid_manifest", "%s", err.Error())
	}
	keys, names := m.PermissionKeys(), m.RouteNames()
	res := Result{Service: service, Permissions: len(keys), Routes: len(names)}
	var st state
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		// Seeds from several services may run at once; ownership checks need them serialised.
		if err := s.catalogue.LockManifests(ctx); err != nil {
			return err
		}
		if err := checkOwnership(ctx, s.catalogue, service, keys, names); err != nil {
			return err
		}
		var err error
		if res.Changed, err = store(ctx, s.catalogue, service, m, keys, names); err != nil || !res.Changed {
			return err
		}
		st, err = s.read(ctx)
		return err
	})
	if err == nil && res.Changed {
		s.publish(ctx, st)
	}
	return res, err
}

// checkOwnership refuses a permission or route another service already declares.
func checkOwnership(ctx context.Context, cat catalogrepo.Repo, service string, keys, names []string) error {
	key, owner, err := cat.PermissionOwner(ctx, keys, service)
	if err == nil {
		return apperror.Fail(apperror.KindConflict, "owned_elsewhere", "permission %q belongs to service %q", key, owner)
	} else if !errors.Is(err, apperror.ErrNotFound) {
		return err
	}
	name, owner, err := cat.RouteOwner(ctx, names, service)
	if err == nil {
		return apperror.Fail(apperror.KindConflict, "owned_elsewhere", "route %q belongs to service %q", name, owner)
	} else if !errors.Is(err, apperror.ErrNotFound) {
		return err
	}
	return nil
}

// store upserts the manifest's entries and deprecates the service's others; it reports whether
// anything changed.
func store(ctx context.Context, cat catalogrepo.Repo, service string, m catalogue.Manifest, keys, names []string) (bool, error) {
	changed := false
	for _, p := range m.Permissions {
		c, err := cat.UpsertPermission(ctx, service, p)
		if err != nil {
			return false, err
		}
		changed = changed || c
	}
	for _, r := range m.Routes {
		c, err := cat.UpsertRoute(ctx, service, r)
		if err != nil {
			return false, err
		}
		changed = changed || c
	}
	n, err := cat.DeprecateRoutes(ctx, service, names)
	if err != nil {
		return false, err
	}
	changed = changed || n > 0
	if n, err = cat.DeprecatePermissions(ctx, service, keys); err != nil {
		return false, err
	}
	return changed || n > 0, nil
}

// state is what a catalogue change publishes: the routes, the consumer set and every role (a
// deprecated permission leaves every role that holds it).
type state struct {
	routes   map[string]string
	consumer []string
	roles    []cache.RoleView
}

// read reads the state in the write's transaction.
func (s *Service) read(ctx context.Context) (st state, err error) {
	if st.routes, err = s.catalogue.RoutesView(ctx); err != nil {
		return st, err
	}
	if st.consumer, err = s.catalogue.ConsumerView(ctx); err != nil {
		return st, err
	}
	st.roles, err = s.roles.View(ctx)
	return st, err
}

func (s *Service) publish(ctx context.Context, st state) {
	s.cache.PutRoutes(ctx, st.routes)
	s.cache.PutConsumer(ctx, st.consumer)
	for _, r := range st.roles {
		s.cache.PutRole(ctx, r)
	}
}

// Permissions lists the live catalogue (what roles can be built from).
func (s *Service) Permissions(ctx context.Context) ([]Permission, error) {
	return s.catalogue.Live(ctx)
}
