package service

import (
	"context"
	"fmt"

	"github.com/tanjed/bus2/authz/internal/db"
)

// ViewService rewrites the whole gateway view from Postgres (at boot: it repairs a missed update
// and fills an empty Redis).
type ViewService struct {
	uow       UnitOfWork
	view      GatewayView
	catalogue CatalogueRepoFactory
	roles     RoleRepoFactory
	companies CompanyRepoFactory
	members   MemberRepoFactory
}

func NewViewService(uow UnitOfWork, view GatewayView, cat CatalogueRepoFactory, roles RoleRepoFactory, companies CompanyRepoFactory, members MemberRepoFactory) *ViewService {
	return &ViewService{uow: uow, view: view, catalogue: cat, roles: roles, companies: companies, members: members}
}

// Rebuild reads the whole view under the exclusive view lock, so no write commits in between,
// and replaces Redis with it.
func (s *ViewService) Rebuild(ctx context.Context) error {
	var snap Snapshot
	err := s.uow.Snapshot(ctx, func(ctx context.Context, q db.Querier) error {
		var err error
		if snap.Routes, err = s.catalogue(q).RoutesView(ctx); err != nil {
			return err
		}
		if snap.Consumer, err = s.catalogue(q).ConsumerView(ctx); err != nil {
			return err
		}
		if snap.Roles, err = s.roles(q).View(ctx); err != nil {
			return err
		}
		if snap.Companies, err = s.companies(q).Statuses(ctx); err != nil {
			return err
		}
		snap.Users, err = s.members(q).Versions(ctx)
		return err
	})
	if err != nil {
		return err
	}
	if err := s.view.Replace(ctx, snap); err != nil {
		return fmt.Errorf("gateway view: %w", err)
	}
	return nil
}
