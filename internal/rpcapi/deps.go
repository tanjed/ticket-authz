package rpcapi

import (
	"context"
	"log/slog"

	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/rbac"
)

// AdminBackend is what AdminService needs from the domain.
type AdminBackend interface {
	Permissions(ctx context.Context) ([]rbac.PermissionInfo, error)
	ListRoles(ctx context.Context, c rbac.Caller) ([]rbac.Role, error)
	GetRole(ctx context.Context, c rbac.Caller, id string) (rbac.Role, error)
	CreateRole(ctx context.Context, c rbac.Caller, in rbac.RoleInput) (rbac.Role, error)
	UpdateRole(ctx context.Context, c rbac.Caller, id string, in rbac.RoleInput) (rbac.Role, error)
	DeleteRole(ctx context.Context, c rbac.Caller, id string) error
	ListMembers(ctx context.Context, c rbac.Caller) ([]rbac.Member, error)
	SetMemberRoles(ctx context.Context, c rbac.Caller, sub string, roleIDs []string) error
	RemoveMember(ctx context.Context, c rbac.Caller, sub string) error
	ListInvitations(ctx context.Context, c rbac.Caller) ([]rbac.Invitation, error)
	CreateInvitation(ctx context.Context, c rbac.Caller, in rbac.InvitationInput) (rbac.Invitation, error)
}

// InternalBackend is what InternalService needs from the domain.
type InternalBackend interface {
	ApplyManifest(ctx context.Context, service string, m catalogue.Manifest) (rbac.ManifestResult, error)
	Claims(ctx context.Context, sub string) (rbac.Claims, error)
	CreateCompany(ctx context.Context, name, adminSub string) (companyID string, created bool, err error)
	SetCompanyStatus(ctx context.Context, companyID, status string) error
	GetInvitation(ctx context.Context, id string) (rbac.Invitation, error)
	AcceptInvitation(ctx context.Context, id, sub string) error
}

// Compile-time checks: the domain satisfies both backends, and the implementations satisfy the
// generated service interfaces.
var (
	_ AdminBackend                          = (*rbac.Service)(nil)
	_ InternalBackend                       = (*rbac.Service)(nil)
	_ authzv1connect.AdminServiceHandler    = (*Admin)(nil)
	_ authzv1connect.InternalServiceHandler = (*Internal)(nil)
	_ authzv1connect.HealthServiceHandler   = (*Health)(nil)
)

func NewAdmin(b AdminBackend, log *slog.Logger) *Admin          { return &Admin{Svc: b, Log: log} }
func NewInternal(b InternalBackend, log *slog.Logger) *Internal { return &Internal{Svc: b, Log: log} }
func NewHealth(c health.Checker, log *slog.Logger) *Health      { return &Health{Checker: c, Log: log} }
