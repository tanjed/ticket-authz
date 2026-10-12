package service_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/service/access"
	"github.com/tanjed/bus2/authz/internal/service/role"
	"github.com/tanjed/bus2/authz/internal/service/user"
)

func TestApplyManifest_IdempotentAndWritesOnlyOnChange(t *testing.T) {
	e := newService(t)
	e.seed(t)
	require.Len(t, e.hash(t, cache.RoutesKey), 4)

	require.NoError(t, e.rdb.HSet(e.ctx, cache.RoutesKey, "marker", "x").Err())
	e.seed(t) // same manifest again
	require.Equal(t, "x", e.hash(t, cache.RoutesKey)["marker"], "a no-op re-seed publishes nothing")

	res, err := e.catalogue.ApplyManifest(e.ctx, "order", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "order:create", Consumer: true}},
		Routes:      []catalogue.Route{{Name: "order.create", Permission: "order:create"}},
	})
	require.NoError(t, err)
	require.True(t, res.Changed)
	require.Equal(t, map[string]string{"order.create": "order:create"}, e.hash(t, cache.RoutesKey),
		"dropped routes are deprecated and unpublished")

	perms, err := e.catalogue.Permissions(e.ctx)
	require.NoError(t, err)
	require.Len(t, perms, 1)

	e.seed(t) // listing them again restores them
	routes := e.hash(t, cache.RoutesKey)
	require.Len(t, routes, 4)
	require.Equal(t, cache.RoutePublic, routes["order.health"])
}

// A permission a manifest stops listing leaves every role holding it, as published.
func TestApplyManifest_DeprecationLeavesRoles(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	clerk, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Clerk", Permissions: []string{"order:read", "order:cancel"}})
	require.NoError(t, err)
	_, err = e.catalogue.ApplyManifest(e.ctx, "order", catalogue.Manifest{Permissions: []catalogue.Permission{{Key: "order:read"}}})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"order:read": "1"}, e.hash(t, cache.RoleKey(id, clerk.ID)))
}

func TestApplyManifest_OwnershipConflict(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, err := e.catalogue.ApplyManifest(e.ctx, "billing", catalogue.Manifest{Permissions: []catalogue.Permission{{Key: "order:create"}}})
	requireStatus(t, err, apperror.KindConflict, "owned_elsewhere")
	_, err = e.catalogue.ApplyManifest(e.ctx, "billing", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "invoice:read"}},
		Routes:      []catalogue.Route{{Name: "order.create", Permission: "invoice:read"}},
	})
	requireStatus(t, err, apperror.KindConflict, "owned_elsewhere")
	_, err = e.catalogue.ApplyManifest(e.ctx, "Bad/Name", catalogue.Manifest{})
	requireStatus(t, err, apperror.KindInvalid, "invalid_service")
}

func TestConsumerView(t *testing.T) {
	e := newService(t)
	e.seed(t)
	members, err := e.rdb.SMembers(e.ctx, cache.ConsumerKey).Result()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"order:create", "order:read"}, members)
}

func TestCreateAdminRole(t *testing.T) {
	e := newService(t)
	id, admin := e.company(t, "acme")

	claims, err := e.companies.Claims(e.ctx, admin.UserID)
	require.NoError(t, err)
	require.Equal(t, id, claims.CompanyID)
	require.Len(t, claims.Roles, 1)
	require.Equal(t, user.AdminRoleName, claims.Roles[0].Name)
	require.Equal(t, map[string]string{"status": "active"}, e.hash(t, cache.CompanyKey(id)))
	require.Equal(t, map[string]string{cache.AllPermission: "1"}, e.hash(t, cache.RoleKey(id, claims.Roles[0].ID)))
	require.Positive(t, claims.AuthzVersion)
	require.Equal(t, claims.AuthzVersion, e.version(t, admin.UserID), "the token's version is the published one")

	// Idempotent: the protected role is reused, the holding ensured, a new version published.
	e.co.members["admin-2"] = id
	roleID, err := e.users.CreateAdminRole(e.ctx, id, admin.UserID)
	require.NoError(t, err)
	require.Equal(t, claims.Roles[0].ID, roleID)
	again, err := e.companies.Claims(e.ctx, admin.UserID)
	require.NoError(t, err)
	require.Len(t, again.Roles, 1)
	require.Greater(t, again.AuthzVersion, claims.AuthzVersion)
	require.Equal(t, again.AuthzVersion, e.version(t, admin.UserID))

	// A second user can be made an Admin of the same company: same role.
	roleID, err = e.users.CreateAdminRole(e.ctx, id, "admin-2")
	require.NoError(t, err)
	require.Equal(t, claims.Roles[0].ID, roleID)
	list, err := e.roles.List(e.ctx, admin)
	require.NoError(t, err)
	require.Len(t, list, 1, "still one Admin role")

	_, err = e.users.CreateAdminRole(e.ctx, "not-a-uuid", "x")
	requireStatus(t, err, apperror.KindInvalid, "invalid_argument")
	_, err = e.users.CreateAdminRole(e.ctx, id, "")
	requireStatus(t, err, apperror.KindInvalid, "invalid_argument")
	require.Equal(t, []string{"MEMBER_ROLES_CHANGED", "MEMBER_ROLES_CHANGED", "MEMBER_ROLES_CHANGED"}, e.ev.names())
}

// A company whose own custom role already took the name cannot get an Admin role by that name.
func TestCreateAdminRole_NameTaken(t *testing.T) {
	e := newService(t)
	id := uuid.NewString()
	_, err := pool.Exec(e.ctx, `INSERT INTO roles (id, company_id, name) VALUES (gen_random_uuid(), $1, 'admin')`, id)
	require.NoError(t, err)
	_, err = e.users.CreateAdminRole(e.ctx, id, "u1")
	requireStatus(t, err, apperror.KindConflict, "name_taken")
}

func TestClaims(t *testing.T) {
	e := newService(t)
	id, admin := e.company(t, "acme")

	_, err := e.companies.Claims(e.ctx, "nobody")
	requireStatus(t, err, apperror.KindNotFound, "not_a_member")

	// Non-active statuses are refused, pending_setup included.
	for _, st := range []string{company.StatusSuspended, company.StatusPendingSetup, ""} {
		e.co.statuses[id] = st
		_, err = e.companies.Claims(e.ctx, admin.UserID)
		requireStatus(t, err, apperror.KindForbidden, "company_suspended")
	}
	e.co.statuses[id] = company.StatusActive
	_, err = e.companies.Claims(e.ctx, admin.UserID)
	require.NoError(t, err)

	// Company unreachable: no claims.
	e.co.down = apperror.Fail(apperror.KindUnavailable, "unavailable", "company service unavailable")
	_, err = e.companies.Claims(e.ctx, admin.UserID)
	requireStatus(t, err, apperror.KindUnavailable, "unavailable")
	e.co.down = nil

	// In Company but not yet given roles by Authz: a company, no roles, version 0.
	e.co.members["fresh"] = id
	c, err := e.companies.Claims(e.ctx, "fresh")
	require.NoError(t, err)
	require.Equal(t, id, c.CompanyID)
	require.Empty(t, c.Roles)
	require.Zero(t, c.AuthzVersion)
}

// SetCompanyStatus only publishes the Redis key; Company owns the status.
func TestSetCompanyStatus_PublishesOnly(t *testing.T) {
	e := newService(t)
	id, _ := e.company(t, "acme")
	require.NoError(t, e.companies.SetStatus(e.ctx, id, "suspended"))
	require.Equal(t, "suspended", e.hash(t, cache.CompanyKey(id))["status"])
	require.NoError(t, e.companies.SetStatus(e.ctx, id, "active"))
	require.Equal(t, "active", e.hash(t, cache.CompanyKey(id))["status"])

	requireStatus(t, e.companies.SetStatus(e.ctx, id, "pending_setup"), apperror.KindInvalid, "invalid_status")
	requireStatus(t, e.companies.SetStatus(e.ctx, "nope", "active"), apperror.KindNotFound, "")
}

func TestRoles_CRUDAndView(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")

	clerk, err := e.roles.Create(e.ctx, admin, role.Input{Name: " Clerk ", Permissions: []string{"order:read", "order:create", "order:read"}})
	require.NoError(t, err)
	require.Equal(t, "Clerk", clerk.Name)
	require.Equal(t, []string{"order:create", "order:read"}, clerk.Permissions)
	require.Equal(t, 1, clerk.Version)
	require.Equal(t, map[string]string{"order:create": "1", "order:read": "1"}, e.hash(t, cache.RoleKey(id, clerk.ID)))

	_, err = e.roles.Create(e.ctx, admin, role.Input{Name: "clerk"})
	requireStatus(t, err, apperror.KindConflict, "name_taken")
	_, err = e.roles.Create(e.ctx, admin, role.Input{Name: "X", Permissions: []string{"order:fly"}})
	requireStatus(t, err, apperror.KindInvalid, "unknown_permission")

	updated, err := e.roles.Update(e.ctx, admin, clerk.ID, role.Input{Name: "Clerk", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	require.Equal(t, 2, updated.Version)
	require.Equal(t, []string{"order:read"}, updated.Permissions)

	require.Equal(t, map[string]string{"order:read": "1"}, e.hash(t, cache.RoleKey(id, clerk.ID)))

	roles, err := e.roles.List(e.ctx, admin)
	require.NoError(t, err)
	require.Len(t, roles, 2)
	var adminRole role.Role
	for _, r := range roles {
		if r.Protected {
			adminRole = r
		}
	}
	_, err = e.roles.Update(e.ctx, admin, adminRole.ID, role.Input{Name: "Boss"})
	requireStatus(t, err, apperror.KindPrecondition, "protected_role")
	requireStatus(t, e.roles.Delete(e.ctx, admin, adminRole.ID), apperror.KindPrecondition, "protected_role")

	require.NoError(t, e.roles.Delete(e.ctx, admin, clerk.ID))
	_, err = e.roles.Get(e.ctx, admin, clerk.ID)
	requireStatus(t, err, apperror.KindNotFound, "")
	require.Empty(t, e.hash(t, cache.RoleKey(id, clerk.ID)))
}

func TestRoles_TenantIsolation(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, acme := e.company(t, "acme")
	_, globex := e.company(t, "globex")
	clerk, err := e.roles.Create(e.ctx, acme, role.Input{Name: "Clerk", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	_, err = e.roles.Get(e.ctx, globex, clerk.ID)
	requireStatus(t, err, apperror.KindNotFound, "")
	_, err = e.roles.Update(e.ctx, globex, clerk.ID, role.Input{Name: "Mine"})
	requireStatus(t, err, apperror.KindNotFound, "")
	requireStatus(t, e.users.SetRoles(e.ctx, globex, globex.UserID, []string{clerk.ID}), apperror.KindInvalid, "unknown_role")
	requireStatus(t, e.users.SetRoles(e.ctx, globex, acme.UserID, nil), apperror.KindNotFound, "")

	// A caller whose headers name a company they don't belong to gets nothing.
	_, err = e.roles.List(e.ctx, access.Caller{UserID: globex.UserID, CompanyID: acme.CompanyID})
	requireStatus(t, err, apperror.KindForbidden, "not_a_member")

	// Role ids of another company are not assignable, and AssignRoles skips them.
	requireStatus(t, e.users.CheckAssignable(e.ctx, globex.CompanyID, globex.UserID, []string{clerk.ID}), apperror.KindNotFound, "not_found")
	e.join(t, globex.CompanyID, "g-staff", clerk.ID)
	c, err := e.companies.Claims(e.ctx, "g-staff")
	require.NoError(t, err)
	require.Empty(t, c.Roles)
}

// A lead with member:manage but not order:cancel cannot hand out order:cancel, the admin role, or
// take roles away from someone more powerful.
func TestEscalation(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, err := e.catalogue.ApplyManifest(e.ctx, "authz", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "role:manage"}, {Key: "member:manage"}},
	})
	require.NoError(t, err)
	id, admin := e.company(t, "acme")

	lead, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Lead", Permissions: []string{"order:read", "role:manage", "member:manage"}})
	require.NoError(t, err)
	cancel, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Canceller", Permissions: []string{"order:cancel"}})
	require.NoError(t, err)
	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	e.join(t, id, "lead-1", lead.ID)
	leadCaller := access.Caller{UserID: "lead-1", CompanyID: id}

	_, err = e.roles.Create(e.ctx, leadCaller, role.Input{Name: "Sneaky", Permissions: []string{"order:cancel"}})
	requireStatus(t, err, apperror.KindForbidden, "escalation")
	_, err = e.roles.Update(e.ctx, leadCaller, cancel.ID, role.Input{Name: "Canceller", Permissions: []string{"order:read"}})
	requireStatus(t, err, apperror.KindForbidden, "escalation")
	requireStatus(t, e.users.SetRoles(e.ctx, leadCaller, "lead-1", []string{lead.ID, cancel.ID}), apperror.KindForbidden, "escalation")
	requireStatus(t, e.users.SetRoles(e.ctx, leadCaller, admin.UserID, nil), apperror.KindForbidden, "escalation")
	requireStatus(t, e.users.CheckAssignable(e.ctx, id, "lead-1", []string{cancel.ID}), apperror.KindForbidden, "escalation")

	// Within their own permissions it works.
	_, err = e.roles.Create(e.ctx, leadCaller, role.Input{Name: "Viewer", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	require.NoError(t, e.users.SetRoles(e.ctx, leadCaller, "lead-1", []string{lead.ID, reader.ID}))
	require.NoError(t, e.users.CheckAssignable(e.ctx, id, "lead-1", []string{reader.ID, lead.ID}))
}

func TestCheckAssignable(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	claims, err := e.companies.Claims(e.ctx, admin.UserID)
	require.NoError(t, err)

	// The Admin holds everything, the Admin role included.
	require.NoError(t, e.users.CheckAssignable(e.ctx, id, admin.UserID, []string{reader.ID, claims.Roles[0].ID}))
	require.NoError(t, e.users.CheckAssignable(e.ctx, id, admin.UserID, nil))
	requireStatus(t, e.users.CheckAssignable(e.ctx, id, admin.UserID, []string{uuid.NewString()}), apperror.KindNotFound, "not_found")
	requireStatus(t, e.users.CheckAssignable(e.ctx, id, admin.UserID, []string{"junk"}), apperror.KindNotFound, "not_found")
	// A caller who is not in the company.
	requireStatus(t, e.users.CheckAssignable(e.ctx, id, "stranger", []string{reader.ID}), apperror.KindForbidden, "not_a_member")
	requireStatus(t, e.users.CheckAssignable(e.ctx, "junk", admin.UserID, nil), apperror.KindInvalid, "invalid_argument")

	// A reader cannot hand out the Admin role.
	e.join(t, id, "reader-1", reader.ID)
	requireStatus(t, e.users.CheckAssignable(e.ctx, id, "reader-1", []string{claims.Roles[0].ID}), apperror.KindForbidden, "escalation")
}

func TestAssignRoles(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	clerk, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Clerk", Permissions: []string{"order:create"}})
	require.NoError(t, err)

	// Unknown role ids are skipped (a role deleted since the invitation was made).
	e.co.members["staff-1"] = id
	require.NoError(t, e.users.AssignRoles(e.ctx, id, "staff-1", []string{reader.ID, uuid.NewString(), "junk"}))
	c, err := e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Equal(t, id, c.CompanyID)
	require.Len(t, c.Roles, 1)
	require.Equal(t, "Reader", c.Roles[0].Name)
	require.Positive(t, c.AuthzVersion)
	require.Equal(t, c.AuthzVersion, e.version(t, "staff-1"))

	// It adds, idempotently, and every call is a new version.
	require.NoError(t, e.users.AssignRoles(e.ctx, id, "staff-1", []string{clerk.ID}))
	require.NoError(t, e.users.AssignRoles(e.ctx, id, "staff-1", []string{clerk.ID}))
	c2, err := e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Len(t, c2.Roles, 2)
	require.Greater(t, c2.AuthzVersion, c.AuthzVersion)
	require.Equal(t, c2.AuthzVersion, e.version(t, "staff-1"))

	// No roles at all is still a user with a version.
	require.NoError(t, e.users.AssignRoles(e.ctx, id, "staff-2", nil))
	require.Positive(t, e.version(t, "staff-2"))
	requireStatus(t, e.users.AssignRoles(e.ctx, "junk", "staff-2", nil), apperror.KindInvalid, "invalid_argument")
	requireStatus(t, e.users.AssignRoles(e.ctx, id, "", nil), apperror.KindInvalid, "invalid_argument")
}

func TestCanRemoveUser(t *testing.T) {
	e := newService(t)
	id, admin := e.company(t, "acme")
	claims, err := e.companies.Claims(e.ctx, admin.UserID)
	require.NoError(t, err)

	ok, reason, err := e.users.CanRemoveUser(e.ctx, id, admin.UserID)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "last_admin", reason)

	// Someone who does not hold the Admin role can always go; so can anyone in a company without one.
	e.join(t, id, "staff-1")
	ok, reason, err = e.users.CanRemoveUser(e.ctx, id, "staff-1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Empty(t, reason)
	ok, _, err = e.users.CanRemoveUser(e.ctx, uuid.NewString(), "x")
	require.NoError(t, err)
	require.True(t, ok)

	// With a second Admin either may go.
	e.join(t, id, "admin-2", claims.Roles[0].ID)
	for _, u := range []string{admin.UserID, "admin-2"} {
		ok, _, err = e.users.CanRemoveUser(e.ctx, id, u)
		require.NoError(t, err)
		require.True(t, ok)
	}
	_, _, err = e.users.CanRemoveUser(e.ctx, "junk", "x")
	requireStatus(t, err, apperror.KindInvalid, "invalid_argument")
}

func TestRevokeUser(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	e.join(t, id, "staff-1", reader.ID)
	v1 := e.version(t, "staff-1")

	require.NoError(t, e.users.RevokeUser(e.ctx, id, "staff-1"))
	v2 := e.version(t, "staff-1")
	require.Greater(t, v2, v1, "the old token is stale at once")
	c, err := e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err) // Company says they still belong (the fake); Authz has no roles for them
	require.Empty(t, c.Roles)
	require.Equal(t, v2, c.AuthzVersion)
	list, err := e.users.ListRoles(e.ctx, admin)
	require.NoError(t, err)
	require.Len(t, list, 1, "only the admin is left holding roles")

	// Idempotent, and fine for a user Authz has never seen.
	require.NoError(t, e.users.RevokeUser(e.ctx, id, "staff-1"))
	require.Greater(t, e.version(t, "staff-1"), v2)
	require.NoError(t, e.users.RevokeUser(e.ctx, id, "never-seen"))
	requireStatus(t, e.users.RevokeUser(e.ctx, "junk", "x"), apperror.KindInvalid, "invalid_argument")

	// A role held by nobody can be deleted again.
	require.NoError(t, e.roles.Delete(e.ctx, admin, reader.ID))
}

func TestSetMemberRoles_NeedsCompanyMembership(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	_, other := e.company(t, "globex")
	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	// In no company, or in another company: not found.
	requireStatus(t, e.users.SetRoles(e.ctx, admin, "ghost", []string{reader.ID}), apperror.KindNotFound, "not_found")
	requireStatus(t, e.users.SetRoles(e.ctx, admin, other.UserID, []string{reader.ID}), apperror.KindNotFound, "not_found")
	// Company unreachable.
	e.co.members["staff-1"] = id
	e.co.down = apperror.Fail(apperror.KindUnavailable, "unavailable", "company service unavailable")
	requireStatus(t, e.users.SetRoles(e.ctx, admin, "staff-1", []string{reader.ID}), apperror.KindUnavailable, "unavailable")
	e.co.down = nil

	require.NoError(t, e.users.SetRoles(e.ctx, admin, "staff-1", []string{reader.ID}))
	c, err := e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Equal(t, "Reader", c.Roles[0].Name)
	require.Equal(t, c.AuthzVersion, e.version(t, "staff-1"))

	list, err := e.users.ListRoles(e.ctx, admin)
	require.NoError(t, err)
	require.Equal(t, []user.UserRoles{
		{UserID: admin.UserID, RoleIDs: list[0].RoleIDs},
		{UserID: "staff-1", RoleIDs: []string{reader.ID}},
	}, list)
	_, err = e.users.ListRoles(e.ctx, access.Caller{UserID: "staff-1", CompanyID: other.CompanyID})
	requireStatus(t, err, apperror.KindForbidden, "not_a_member")
}

func TestLastAdmin(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	claims, err := e.companies.Claims(e.ctx, admin.UserID)
	require.NoError(t, err)
	adminRole := claims.Roles[0].ID

	requireStatus(t, e.users.SetRoles(e.ctx, admin, admin.UserID, nil), apperror.KindPrecondition, "last_admin")

	e.join(t, id, "admin-2", adminRole)
	// With a second admin, the first may step down.
	require.NoError(t, e.users.SetRoles(e.ctx, admin, admin.UserID, nil))
	second := access.Caller{UserID: "admin-2", CompanyID: id}
	requireStatus(t, e.users.SetRoles(e.ctx, second, "admin-2", nil), apperror.KindPrecondition, "last_admin")

	list, err := e.users.ListRoles(e.ctx, second)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, []string{adminRole}, list[0].RoleIDs)
}

// A user's version changes with their roles, is never reused, and survives a move to another company.
func TestAuthzVersion(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	e.join(t, id, "staff-1")
	v1 := e.version(t, "staff-1")

	// A role edit applies through the role's key: no version change, no refresh needed.
	_, err = e.roles.Update(e.ctx, admin, reader.ID, role.Input{Name: "Reader", Permissions: []string{"order:create"}})
	require.NoError(t, err)
	require.Equal(t, v1, e.version(t, "staff-1"))

	// An assignment change does: the old token is stale.
	require.NoError(t, e.users.SetRoles(e.ctx, admin, "staff-1", []string{reader.ID}))
	v2 := e.version(t, "staff-1")
	require.Greater(t, v2, v1)
	claims, err := e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Equal(t, v2, claims.AuthzVersion)

	// Revoked, then in another company: a version never seen before, and no roles left behind.
	require.NoError(t, e.users.RevokeUser(e.ctx, id, "staff-1"))
	v3 := e.version(t, "staff-1")
	require.Greater(t, v3, v2)
	other, _ := e.company(t, "globex")
	e.join(t, other, "staff-1")
	require.Greater(t, e.version(t, "staff-1"), v3)
	claims, err = e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Equal(t, other, claims.CompanyID)
	require.Empty(t, claims.Roles)
}

// The boot resync rewrites everything from Postgres and Company and deletes keys it no longer has.
func TestResync(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	pending := uuid.NewString()
	suspended := uuid.NewString()
	e.co.statuses[pending] = company.StatusPendingSetup
	e.co.statuses[suspended] = company.StatusSuspended
	require.NoError(t, e.rdb.FlushAll(e.ctx).Err())
	require.NoError(t, e.rdb.Set(e.ctx, cache.UserVersionKey("ghost"), 7, 0).Err())
	require.NoError(t, e.rdb.Set(e.ctx, "other:key", 1, 0).Err())

	require.NoError(t, e.resync.Resync(e.ctx))
	require.Len(t, e.hash(t, cache.RoutesKey), 4)
	require.Equal(t, "active", e.hash(t, cache.CompanyKey(id))["status"])
	require.Equal(t, "suspended", e.hash(t, cache.CompanyKey(suspended))["status"])
	require.Empty(t, e.hash(t, cache.CompanyKey(pending)), "pending_setup is not published")
	claims, err := e.companies.Claims(e.ctx, admin.UserID)
	require.NoError(t, err)
	require.Equal(t, claims.AuthzVersion, e.version(t, admin.UserID))
	require.Equal(t, map[string]string{cache.AllPermission: "1"}, e.hash(t, cache.RoleKey(id, claims.Roles[0].ID)))
	require.Zero(t, e.version(t, "ghost"), "an unknown user's key is deleted")
	n, err := e.rdb.Exists(e.ctx, "other:key").Result()
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "keys outside authz: are not Authz's")

	// Company unreachable: the resync (and so the boot) fails.
	e.co.down = apperror.Fail(apperror.KindUnavailable, "unavailable", "company service unavailable")
	require.Error(t, e.resync.Resync(e.ctx))
}

func TestApplyManifest_AuthenticatedRoute(t *testing.T) {
	e := newService(t)
	_, err := e.catalogue.ApplyManifest(e.ctx, "authz", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "role:read"}},
		Routes: []catalogue.Route{
			{Name: "authz.me", Authenticated: true},
			{Name: "authz.roles.list", Permission: "role:read"},
			{Name: "authz.health", Public: true},
		},
	})
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"authz.me": cache.RouteAuthenticated, "authz.roles.list": "role:read", "authz.health": cache.RoutePublic,
	}, e.hash(t, cache.RoutesKey))

	// A route with two modes, or none, is refused with invalid_route.
	for _, r := range []catalogue.Route{
		{Name: "x", Authenticated: true, Public: true},
		{Name: "x", Authenticated: true, Permission: "role:read"},
		{Name: "x"},
	} {
		_, err = e.catalogue.ApplyManifest(e.ctx, "authz", catalogue.Manifest{
			Permissions: []catalogue.Permission{{Key: "role:read"}}, Routes: []catalogue.Route{r},
		})
		requireStatus(t, err, apperror.KindInvalid, "invalid_route")
	}

	// Changing a route's mode is a change (it is republished).
	res, err := e.catalogue.ApplyManifest(e.ctx, "authz", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "role:read"}},
		Routes: []catalogue.Route{
			{Name: "authz.me", Permission: "role:read"},
			{Name: "authz.roles.list", Permission: "role:read"},
			{Name: "authz.health", Public: true},
		},
	})
	require.NoError(t, err)
	require.True(t, res.Changed)
	require.Equal(t, "role:read", e.hash(t, cache.RoutesKey)["authz.me"])
}

func TestRoles_LandingPath(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")

	clerk, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Clerk", Permissions: []string{"order:read"}, LandingPath: "/buses"})
	require.NoError(t, err)
	require.Equal(t, "/buses", clerk.LandingPath)
	_, err = e.roles.Create(e.ctx, admin, role.Input{Name: "Bad", LandingPath: "//evil.com"})
	requireStatus(t, err, apperror.KindInvalid, "invalid_landing_path")

	// Landing path only: no version bump, nothing republished.
	key := cache.RoleKey(id, clerk.ID)
	require.NoError(t, e.rdb.HSet(e.ctx, key, "marker", "x").Err())
	got, err := e.roles.Update(e.ctx, admin, clerk.ID, role.Input{Name: "Clerk", Permissions: []string{"order:read"}, LandingPath: "/team"})
	require.NoError(t, err)
	require.Equal(t, "/team", got.LandingPath)
	require.Equal(t, 1, got.Version)
	require.Equal(t, "x", e.hash(t, key)["marker"], "a landing-only change publishes nothing")

	// A real change bumps the version, republishes and keeps the landing path set in the same call.
	got, err = e.roles.Update(e.ctx, admin, clerk.ID, role.Input{Name: "Clerk", Permissions: []string{"order:read", "order:create"}, LandingPath: ""})
	require.NoError(t, err)
	require.Equal(t, 2, got.Version)
	require.Equal(t, "", got.LandingPath)
	require.Equal(t, map[string]string{"order:create": "1", "order:read": "1"}, e.hash(t, key))

	// The Admin role may change its landing path only.
	roles, err := e.roles.List(e.ctx, admin)
	require.NoError(t, err)
	var adminRole role.Role
	for _, r := range roles {
		if r.Protected {
			adminRole = r
		}
	}
	got, err = e.roles.Update(e.ctx, admin, adminRole.ID, role.Input{Name: adminRole.Name, LandingPath: "/welcome"})
	require.NoError(t, err)
	require.Equal(t, "/welcome", got.LandingPath)
	require.Equal(t, adminRole.Version, got.Version)
	_, err = e.roles.Update(e.ctx, admin, adminRole.ID, role.Input{Name: "Boss", LandingPath: "/welcome"})
	requireStatus(t, err, apperror.KindPrecondition, "protected_role")
	_, err = e.roles.Update(e.ctx, admin, adminRole.ID, role.Input{Name: adminRole.Name, Permissions: []string{"order:read"}})
	requireStatus(t, err, apperror.KindPrecondition, "protected_role")
	_, err = e.roles.Update(e.ctx, admin, adminRole.ID, role.Input{Name: adminRole.Name, LandingPath: "nope"})
	requireStatus(t, err, apperror.KindInvalid, "invalid_landing_path")
}

func TestRoles_LandingPath_Escalation(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	e.join(t, id, "reader-1", reader.ID)
	rc := access.Caller{UserID: "reader-1", CompanyID: id}
	roles, err := e.roles.List(e.ctx, admin)
	require.NoError(t, err)
	for _, r := range roles {
		if r.Protected {
			_, err = e.roles.Update(e.ctx, rc, r.ID, role.Input{Name: r.Name, LandingPath: "/x"})
			requireStatus(t, err, apperror.KindForbidden, "escalation")
		}
	}
}

func TestMe(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")

	me, err := e.users.Me(e.ctx, admin)
	require.NoError(t, err)
	require.Equal(t, []string{"*"}, me.Permissions)
	require.Equal(t, admin.UserID, me.UserID)
	require.Equal(t, id, me.CompanyID)
	require.Len(t, me.Roles, 1)

	reader, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Reader", Permissions: []string{"order:read", "order:create"}, LandingPath: "/buses"})
	require.NoError(t, err)
	canceller, err := e.roles.Create(e.ctx, admin, role.Input{Name: "Canceller", Permissions: []string{"order:cancel", "order:read"}})
	require.NoError(t, err)
	e.join(t, id, "staff-1", reader.ID, canceller.ID)

	me, err = e.users.Me(e.ctx, access.Caller{UserID: "staff-1", CompanyID: id})
	require.NoError(t, err)
	require.Equal(t, []string{"order:cancel", "order:create", "order:read"}, me.Permissions, "sorted union")
	require.Equal(t, []user.MeRole{
		{ID: canceller.ID, Name: "Canceller"}, {ID: reader.ID, Name: "Reader", LandingPath: "/buses"},
	}, me.Roles)

	// Fresh from the database: a role edit shows at once, a deprecated permission is gone.
	_, err = e.roles.Update(e.ctx, admin, reader.ID, role.Input{Name: "Reader", Permissions: []string{"order:read"}, LandingPath: "/buses"})
	require.NoError(t, err)
	me, err = e.users.Me(e.ctx, access.Caller{UserID: "staff-1", CompanyID: id})
	require.NoError(t, err)
	require.Equal(t, []string{"order:cancel", "order:read"}, me.Permissions)

	// Not a member of the company named.
	_, err = e.users.Me(e.ctx, access.Caller{UserID: "staff-1", CompanyID: uuid.NewString()})
	requireStatus(t, err, apperror.KindForbidden, "not_a_member")
}
