package service

import "context"

// The gateway view: what the gateway decides every request from, kept in Redis (internal/redisview)
// and read there from a replica. Postgres is the truth; each write updates the keys it changed
// after its commit (UnitOfWork.Write), and ViewService.Rebuild rewrites everything at boot.

// Route values besides a permission key, and the permission a grants_all role holds.
const (
	RoutePublic   = "public"
	AllPermission = "*"
)

// GatewayView is the gateway view's store. Every Put replaces its key whole.
type GatewayView interface {
	PutRoutes(ctx context.Context, routes map[string]string) error
	PutConsumer(ctx context.Context, permissions []string) error
	PutCompany(ctx context.Context, companyID, status string) error
	PutRole(ctx context.Context, r RoleView) error
	DeleteRole(ctx context.Context, companyID, roleID string) error
	PutUserVersion(ctx context.Context, sub string, version int64) error
	DeleteUser(ctx context.Context, sub string) error
	// Replace writes the whole view and deletes every key it does not list.
	Replace(ctx context.Context, s Snapshot) error
}

// Snapshot is the whole gateway view.
type Snapshot struct {
	Routes    map[string]string // route name -> permission key, or RoutePublic
	Consumer  []string
	Companies map[string]string // company id -> status
	Roles     []RoleView
	Users     map[string]int64 // sub -> authorization version
}

// RoleView is a role's live permissions; a grants_all role holds AllPermission only.
type RoleView struct {
	CompanyID, RoleID string
	Permissions       []string
}
