// Package internalapi serves InternalService: seed Jobs, the IdP and platform operations, on the
// internal listener only. Each method decodes, calls a service and maps the result; the rules live
// in internal/service.
package internalapi

import (
	"context"
	"log/slog"

	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service"
)

// The services InternalService calls, each as narrow as its methods here.
type (
	Catalogue interface {
		ApplyManifest(ctx context.Context, svc string, m catalogue.Manifest) (service.ManifestResult, error)
	}
	Companies interface {
		Claims(ctx context.Context, sub string) (service.Claims, error)
		Create(ctx context.Context, name, adminSub string) (companyID string, created bool, err error)
		SetStatus(ctx context.Context, companyID, status string) error
	}
	Invitations interface {
		Get(ctx context.Context, id string) (service.Invitation, error)
		Accept(ctx context.Context, id, sub string) error
	}
)

var (
	_ Catalogue                             = (*service.CatalogueService)(nil)
	_ Companies                             = (*service.CompanyService)(nil)
	_ Invitations                           = (*service.InvitationService)(nil)
	_ authzv1connect.InternalServiceHandler = (*Internal)(nil)
)

// Internal implements InternalService.
type Internal struct {
	authzv1connect.UnimplementedInternalServiceHandler
	Catalogue   Catalogue
	Companies   Companies
	Invitations Invitations
	Log         *slog.Logger
}

func New(cat *service.CatalogueService, companies *service.CompanyService, invitations *service.InvitationService, log *slog.Logger) *Internal {
	return &Internal{Catalogue: cat, Companies: companies, Invitations: invitations, Log: log}
}

// Register serves InternalService on the internal listener only.
func (s *Internal) Register(r router.Registrar) {
	r.Internal(authzv1connect.NewInternalServiceHandler(s, r.HandlerOptions()...))
}
