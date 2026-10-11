// Package internalapi serves InternalService: seed Jobs, the IdP and platform operations, on the
// internal listener only. Each method decodes, calls a service and maps the result; the rules live
// in internal/service.
package internalapi

import (
	"context"

	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	catalogsvc "github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/company"
	"github.com/tanjed/bus2/authz/internal/service/invitation"
)

// The services InternalService calls, each as narrow as its methods here.
type (
	Catalogue interface {
		ApplyManifest(ctx context.Context, svc string, m catalogue.Manifest) (catalogsvc.Result, error)
	}
	Companies interface {
		Claims(ctx context.Context, sub string) (company.Claims, error)
		Create(ctx context.Context, name, adminSub string) (companyID string, created bool, err error)
		SetStatus(ctx context.Context, companyID, status string) error
	}
	Invitations interface {
		Get(ctx context.Context, id string) (invitation.Invitation, error)
		Accept(ctx context.Context, id, sub string) error
	}
)

var (
	_ Catalogue                             = (*catalogsvc.Service)(nil)
	_ Companies                             = (*company.Service)(nil)
	_ Invitations                           = (*invitation.Service)(nil)
	_ authzv1connect.InternalServiceHandler = (*Internal)(nil)
)

// Internal implements InternalService.
type Internal struct {
	authzv1connect.UnimplementedInternalServiceHandler
	Catalogue   Catalogue
	Companies   Companies
	Invitations Invitations
}
