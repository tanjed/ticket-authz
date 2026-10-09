package service

import (
	"context"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/db"
)

// The ports: what the services need from storage. internal/repository implements them over
// Postgres; each is built per call from a db.Querier (the pool, or the unit of work's transaction)
// by its factory, which fx provides (repository.Module).
//
// A missing row is ErrNotFound and a unique violation ErrDuplicate; anything else is a raw error.

// UnitOfWork runs a service's repository calls together.
type UnitOfWork interface {
	// Write takes the gateway view lock (shared), runs fn in one transaction and, once it has
	// committed, runs project on the pool to update the gateway view. A failed project is logged,
	// not returned: the write is committed, and the next boot's Rebuild repairs the view.
	Write(ctx context.Context, fn func(context.Context, db.Querier) error, project func(context.Context, db.Querier) error) error
	// Read runs fn on the pool: no lock, no transaction.
	Read(ctx context.Context, fn func(context.Context, db.Querier) error) error
	// Snapshot takes the gateway view lock exclusively and runs fn in a repeatable-read, read-only
	// transaction: no write commits while the whole view is read and replaced.
	Snapshot(ctx context.Context, fn func(context.Context, db.Querier) error) error
}

type (
	CatalogueRepoFactory  func(db.Querier) CatalogueRepo
	CompanyRepoFactory    func(db.Querier) CompanyRepo
	RoleRepoFactory       func(db.Querier) RoleRepo
	MemberRepoFactory     func(db.Querier) MemberRepo
	InvitationRepoFactory func(db.Querier) InvitationRepo
)

// CatalogueRepo is the permissions and routes services declare in their manifests.
type CatalogueRepo interface {
	// LockManifests serialises manifest applies until the transaction ends.
	LockManifests(ctx context.Context) error
	// PermissionOwner returns the first of keys owned by a service other than service.
	PermissionOwner(ctx context.Context, keys []string, service string) (key, owner string, err error)
	// RouteOwner returns the first of names owned by a service other than service.
	RouteOwner(ctx context.Context, names []string, service string) (name, owner string, err error)
	// UpsertPermission and UpsertRoute store one entry (and undeprecate it); changed is false
	// when it was stored as is.
	UpsertPermission(ctx context.Context, service string, p catalogue.Permission) (changed bool, err error)
	UpsertRoute(ctx context.Context, service string, r catalogue.Route) (changed bool, err error)
	// DeprecatePermissions and DeprecateRoutes deprecate the service's live entries not in keep.
	DeprecatePermissions(ctx context.Context, service string, keep []string) (int64, error)
	DeprecateRoutes(ctx context.Context, service string, keep []string) (int64, error)
	// Live lists the live permissions; LiveKeys is those of keys that are live.
	Live(ctx context.Context) ([]PermissionInfo, error)
	LiveKeys(ctx context.Context, keys []string) ([]string, error)
	// RoutesView and ConsumerView are the catalogue's part of the gateway view.
	RoutesView(ctx context.Context) (map[string]string, error)
	ConsumerView(ctx context.Context) ([]string, error)
}

type CompanyRepo interface {
	Create(ctx context.Context, id, name string) error
	// SetStatus reports whether the status changed; ErrNotFound if there is no such company.
	SetStatus(ctx context.Context, id, status string) (changed bool, err error)
	Name(ctx context.Context, id string) (string, error)
	// Statuses is every company's status, for the gateway view.
	Statuses(ctx context.Context) (map[string]string, error)
}

// RoleRepo: every query is scoped by company (invariant 4) except those by a role id already
// checked against the company (Lock, Find).
type RoleRepo interface {
	List(ctx context.Context, companyID string) ([]Role, error)
	// Find returns those of ids that are roles of the company.
	Find(ctx context.Context, companyID string, ids []string) (map[string]Role, error)
	// Lock loads a role of the company and locks it until the transaction ends.
	Lock(ctx context.Context, companyID, id string) (Role, error)
	// Create stores a role (no permissions); ErrDuplicate if the name is taken.
	Create(ctx context.Context, companyID string, r Role) error
	// Rename renames a role and bumps its version; ErrDuplicate if the name is taken.
	Rename(ctx context.Context, id, name string) error
	// SetPermissions replaces a role's permissions.
	SetPermissions(ctx context.Context, id string, keys []string) error
	Delete(ctx context.Context, id string) error
	// Assigned reports whether any member holds the role.
	Assigned(ctx context.Context, id string) (bool, error)
	// View is the gateway view of the given roles, or of every role when ids is empty.
	View(ctx context.Context, ids ...string) ([]RoleView, error)
}

type MemberRepo interface {
	IsMember(ctx context.Context, sub, companyID string) (bool, error)
	// Grants is what a subject's roles grant: everything, or these permissions.
	Grants(ctx context.Context, sub string) (all bool, permissions []string, err error)
	// CompanyOf is the subject's company, or "" if none.
	CompanyOf(ctx context.Context, sub string) (string, error)
	// Membership is the subject's company, its status and the subject's authorization version.
	Membership(ctx context.Context, sub string) (Membership, error)
	RoleRefs(ctx context.Context, sub string) ([]RoleRef, error)
	List(ctx context.Context, companyID string) ([]Member, error)
	// Create adds a member and returns its authorization version; ErrDuplicate if the subject
	// already belongs to a company.
	Create(ctx context.Context, sub, companyID string) (version int64, err error)
	// Lock locks a member of the company and returns their role ids.
	Lock(ctx context.Context, companyID, sub string) (roleIDs []string, err error)
	// ReplaceRoles sets the member's roles to roleIDs.
	ReplaceRoles(ctx context.Context, companyID, sub string, roleIDs []string) error
	// AddExistingRoles assigns those of roleIDs that are still roles of the company.
	AddExistingRoles(ctx context.Context, companyID, sub string, roleIDs []string) error
	// BumpVersion gives the member a new authorization version (never reused, invariant 10).
	BumpVersion(ctx context.Context, sub string) (int64, error)
	Delete(ctx context.Context, sub string) error
	// OtherHolders counts the company's members other than sub holding the role.
	OtherHolders(ctx context.Context, companyID, roleID, sub string) (int, error)
	// Versions is every member's authorization version, for the gateway view.
	Versions(ctx context.Context) (map[string]int64, error)
}

type InvitationRepo interface {
	// ExpirePending expires the company's pending invitations for the phone.
	ExpirePending(ctx context.Context, companyID, phone string) error
	Create(ctx context.Context, inv Invitation) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, companyID string) ([]Invitation, error)
	Get(ctx context.Context, id string) (Invitation, error)
	// LockPending loads an invitation for acceptance and locks it until the transaction ends.
	LockPending(ctx context.Context, id string) (PendingInvitation, error)
	MarkAccepted(ctx context.Context, id, sub string) error
}

// write runs fn and project through the unit of work, each with the repositories bind builds over
// its querier.
func write[R any](ctx context.Context, u UnitOfWork, bind func(db.Querier) R, fn func(context.Context, R) error, project func(context.Context, R) error) error {
	var p func(context.Context, db.Querier) error
	if project != nil {
		p = func(ctx context.Context, q db.Querier) error { return project(ctx, bind(q)) }
	}
	return u.Write(ctx, func(ctx context.Context, q db.Querier) error { return fn(ctx, bind(q)) }, p)
}

// read runs fn on the pool with the repositories bind builds.
func read[R any](ctx context.Context, u UnitOfWork, bind func(db.Querier) R, fn func(context.Context, R) error) error {
	return u.Read(ctx, func(ctx context.Context, q db.Querier) error { return fn(ctx, bind(q)) })
}
