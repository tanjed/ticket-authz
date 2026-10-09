package service

import (
	"context"
	"errors"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/db"
)

// CatalogueService applies service manifests (permissions and routes) and lists the catalogue.
type CatalogueService struct {
	uow       UnitOfWork
	view      GatewayView
	catalogue CatalogueRepoFactory
	roles     RoleRepoFactory
}

type catalogueRepos struct {
	catalogue CatalogueRepo
	roles     RoleRepo
}

func NewCatalogueService(uow UnitOfWork, view GatewayView, cat CatalogueRepoFactory, roles RoleRepoFactory) *CatalogueService {
	return &CatalogueService{uow: uow, view: view, catalogue: cat, roles: roles}
}

func (s *CatalogueService) bind(q db.Querier) catalogueRepos {
	return catalogueRepos{catalogue: s.catalogue(q), roles: s.roles(q)}
}

// ApplyManifest replaces a service's permissions and routes. Anything the service no longer lists
// is deprecated, never deleted (role links survive a rollback); listing it again restores it.
func (s *CatalogueService) ApplyManifest(ctx context.Context, service string, m catalogue.Manifest) (ManifestResult, error) {
	if !catalogue.ValidService(service) {
		return ManifestResult{}, fail(KindInvalid, "invalid_service", "invalid service name %q", service)
	}
	if err := m.Validate(); err != nil {
		return ManifestResult{}, fail(KindInvalid, "invalid_manifest", "%s", err.Error())
	}
	keys, names := m.PermissionKeys(), m.RouteNames()
	res := ManifestResult{Service: service, Permissions: len(keys), Routes: len(names)}
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r catalogueRepos) error {
		// Seeds from several services may run at once; ownership checks need them serialised.
		if err := r.catalogue.LockManifests(ctx); err != nil {
			return err
		}
		if err := checkOwnership(ctx, r.catalogue, service, keys, names); err != nil {
			return err
		}
		var err error
		res.Changed, err = store(ctx, r.catalogue, service, m, keys, names)
		return err
	}, func(ctx context.Context, r catalogueRepos) error {
		if !res.Changed {
			return nil
		}
		return s.putCatalogue(ctx, r)
	})
	return res, err
}

// checkOwnership refuses a permission or route another service already declares.
func checkOwnership(ctx context.Context, cat CatalogueRepo, service string, keys, names []string) error {
	key, owner, err := cat.PermissionOwner(ctx, keys, service)
	if err == nil {
		return fail(KindConflict, "owned_elsewhere", "permission %q belongs to service %q", key, owner)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	name, owner, err := cat.RouteOwner(ctx, names, service)
	if err == nil {
		return fail(KindConflict, "owned_elsewhere", "route %q belongs to service %q", name, owner)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	return nil
}

// store upserts the manifest's entries and deprecates the service's others; it reports whether
// anything changed.
func store(ctx context.Context, cat CatalogueRepo, service string, m catalogue.Manifest, keys, names []string) (bool, error) {
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

// putCatalogue updates the routes, the consumer set and every role: a deprecated permission
// leaves every role that holds it.
func (s *CatalogueService) putCatalogue(ctx context.Context, r catalogueRepos) error {
	routes, err := r.catalogue.RoutesView(ctx)
	if err != nil {
		return err
	}
	consumer, err := r.catalogue.ConsumerView(ctx)
	if err != nil {
		return err
	}
	roles, err := r.roles.View(ctx)
	if err != nil {
		return err
	}
	errs := []error{s.view.PutRoutes(ctx, routes), s.view.PutConsumer(ctx, consumer)}
	for _, role := range roles {
		errs = append(errs, s.view.PutRole(ctx, role))
	}
	return errors.Join(errs...)
}

// Permissions lists the live catalogue (what roles can be built from).
func (s *CatalogueService) Permissions(ctx context.Context) ([]PermissionInfo, error) {
	var out []PermissionInfo
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r catalogueRepos) (err error) {
		out, err = r.catalogue.Live(ctx)
		return err
	})
	return out, err
}
