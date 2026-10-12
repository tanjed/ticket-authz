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
	"github.com/tanjed/bus2/authz/internal/service/user"
)

// The services InternalService calls, each as narrow as its methods here.
type (
	Catalogue interface {
		ApplyManifest(ctx context.Context, svc string, m catalogue.Manifest) (catalogsvc.Result, error)
	}
	Companies interface {
		Claims(ctx context.Context, userID string) (company.Claims, error)
		SetStatus(ctx context.Context, companyID, status string) error
	}
	Users interface {
		CreateAdminRole(ctx context.Context, companyID, userID string) (roleID string, err error)
		AssignRoles(ctx context.Context, companyID, userID string, roleIDs []string) error
		CheckAssignable(ctx context.Context, companyID, callerUserID string, roleIDs []string) error
		CanRemoveUser(ctx context.Context, companyID, userID string) (removable bool, reason string, err error)
		RevokeUser(ctx context.Context, companyID, userID string) error
	}
)

var (
	_ Catalogue                             = (*catalogsvc.Service)(nil)
	_ Companies                             = (*company.Service)(nil)
	_ Users                                 = (*user.Service)(nil)
	_ authzv1connect.InternalServiceHandler = (*Internal)(nil)
)

// Internal implements InternalService.
type Internal struct {
	authzv1connect.UnimplementedInternalServiceHandler
	Catalogue Catalogue
	Companies Companies
	Users     Users
}
