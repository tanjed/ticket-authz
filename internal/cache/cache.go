// Package cache publishes Authz's authorization state to Redis after every change, for the API
// gateway (APISIX, ../APISIX) to read: routes, the consumer permissions, company status, each
// role's permissions and each member's authorization version. Authz writes what changed, when
// it changes; nothing more. The key layout is the contract with ../APISIX.
package cache

import "context"

// Route values besides a permission key, and the permission a grants_all role holds.
const (
	RoutePublic        = "public"
	RouteAuthenticated = "authenticated"
	AllPermission      = "*"
)

// Publisher writes the state to Redis. Each Put replaces its key whole. Publishing is best effort:
// a failure is logged, never returned (the change is already committed in Postgres).
type Publisher interface {
	PutRoutes(ctx context.Context, routes map[string]string)
	PutConsumer(ctx context.Context, permissions []string)
	PutCompany(ctx context.Context, companyID, status string)
	PutRole(ctx context.Context, r RoleView)
	DeleteRole(ctx context.Context, companyID, roleID string)
	PutUserVersion(ctx context.Context, sub string, version int64)
	DeleteUser(ctx context.Context, sub string)
	// Replace writes the whole state and deletes every other key Authz owns (the boot resync).
	// Unlike the Puts it returns its error: a failed resync fails the boot.
	Replace(ctx context.Context, s State) error
}

// State is everything Authz publishes.
type State struct {
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
