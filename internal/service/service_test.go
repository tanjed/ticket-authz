package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/redisview"
	"github.com/tanjed/bus2/authz/internal/service"
)

func TestApplyManifest_IdempotentAndWritesOnlyOnChange(t *testing.T) {
	e := newService(t)
	e.seed(t)
	require.Len(t, e.hash(t, redisview.RoutesKey), 4)

	require.NoError(t, e.rdb.HSet(e.ctx, redisview.RoutesKey, "marker", "x").Err())
	e.seed(t) // same manifest again
	require.Equal(t, "x", e.hash(t, redisview.RoutesKey)["marker"], "a no-op re-seed must not write the view")

	res, err := e.catalogue.ApplyManifest(e.ctx, "order", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "order:create", Consumer: true}},
		Routes:      []catalogue.Route{{Name: "order.create", Permission: "order:create"}},
	})
	require.NoError(t, err)
	require.True(t, res.Changed)
	require.Equal(t, map[string]string{"order.create": "order:create"}, e.hash(t, redisview.RoutesKey),
		"dropped routes are deprecated and leave the view")

	perms, err := e.catalogue.Permissions(e.ctx)
	require.NoError(t, err)
	require.Len(t, perms, 1)

	e.seed(t) // listing them again restores them
	routes := e.hash(t, redisview.RoutesKey)
	require.Len(t, routes, 4)
	require.Equal(t, service.RoutePublic, routes["order.health"])
}

// A permission a manifest stops listing leaves every role holding it, in the view.
func TestApplyManifest_DeprecationLeavesRoles(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	role, err := e.roles.Create(e.ctx, admin, service.RoleInput{Name: "Clerk", Permissions: []string{"order:read", "order:cancel"}})
	require.NoError(t, err)
	_, err = e.catalogue.ApplyManifest(e.ctx, "order", catalogue.Manifest{Permissions: []catalogue.Permission{{Key: "order:read"}}})
	require.NoError(t, err)
	require.Equal(t, map[string]string{"order:read": "1"}, e.hash(t, redisview.RoleKey(id, role.ID)))
}

func TestApplyManifest_OwnershipConflict(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, err := e.catalogue.ApplyManifest(e.ctx, "billing", catalogue.Manifest{Permissions: []catalogue.Permission{{Key: "order:create"}}})
	requireStatus(t, err, service.KindConflict, "owned_elsewhere")
	_, err = e.catalogue.ApplyManifest(e.ctx, "billing", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "invoice:read"}},
		Routes:      []catalogue.Route{{Name: "order.create", Permission: "invoice:read"}},
	})
	requireStatus(t, err, service.KindConflict, "owned_elsewhere")
	_, err = e.catalogue.ApplyManifest(e.ctx, "Bad/Name", catalogue.Manifest{})
	requireStatus(t, err, service.KindInvalid, "invalid_service")
}

func TestConsumerView(t *testing.T) {
	e := newService(t)
	e.seed(t)
	members, err := e.rdb.SMembers(e.ctx, redisview.ConsumerKey).Result()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"order:create", "order:read"}, members)
}

func TestCreateCompany_AndClaims(t *testing.T) {
	e := newService(t)
	id, admin := e.company(t, "acme")

	claims, err := e.companies.Claims(e.ctx, admin.Sub)
	require.NoError(t, err)
	require.Equal(t, id, claims.CompanyID)
	require.Len(t, claims.Roles, 1)
	require.Equal(t, service.AdminRoleName, claims.Roles[0].Name)

	// Idempotent per subject.
	again, created, err := e.companies.Create(e.ctx, "other name", admin.Sub)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, id, again)

	_, err = e.companies.Claims(e.ctx, "nobody")
	requireStatus(t, err, service.KindNotFound, "not_a_member")

	_, _, err = e.companies.Create(e.ctx, "  ", "x")
	requireStatus(t, err, service.KindInvalid, "invalid_name")

	require.Equal(t, map[string]string{"status": "active"}, e.hash(t, redisview.CompanyKey(id)))
	require.Equal(t, map[string]string{service.AllPermission: "1"}, e.hash(t, redisview.RoleKey(id, claims.Roles[0].ID)))
	require.Positive(t, claims.AuthzVersion)
	require.Equal(t, claims.AuthzVersion, e.version(t, admin.Sub), "the token's version is the view's")
	require.Equal(t, []string{"COMPANY_REGISTERED"}, e.ev.names())
}

func TestSuspendedCompany(t *testing.T) {
	e := newService(t)
	id, admin := e.company(t, "acme")
	require.NoError(t, e.companies.SetStatus(e.ctx, id, "suspended"))
	_, err := e.companies.Claims(e.ctx, admin.Sub)
	requireStatus(t, err, service.KindForbidden, "company_suspended")
	require.Equal(t, "suspended", e.hash(t, redisview.CompanyKey(id))["status"])

	require.NoError(t, e.companies.SetStatus(e.ctx, id, "active"))
	_, err = e.companies.Claims(e.ctx, admin.Sub)
	require.NoError(t, err)
	requireStatus(t, e.companies.SetStatus(e.ctx, "5f1d3c1e-0000-4000-8000-000000000000", "active"), service.KindNotFound, "")
}

func TestRoles_CRUDAndView(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")

	clerk, err := e.roles.Create(e.ctx, admin, service.RoleInput{Name: " Clerk ", Permissions: []string{"order:read", "order:create", "order:read"}})
	require.NoError(t, err)
	require.Equal(t, "Clerk", clerk.Name)
	require.Equal(t, []string{"order:create", "order:read"}, clerk.Permissions)
	require.Equal(t, 1, clerk.Version)
	require.Equal(t, map[string]string{"order:create": "1", "order:read": "1"}, e.hash(t, redisview.RoleKey(id, clerk.ID)))

	_, err = e.roles.Create(e.ctx, admin, service.RoleInput{Name: "clerk"})
	requireStatus(t, err, service.KindConflict, "name_taken")
	_, err = e.roles.Create(e.ctx, admin, service.RoleInput{Name: "X", Permissions: []string{"order:fly"}})
	requireStatus(t, err, service.KindInvalid, "unknown_permission")

	updated, err := e.roles.Update(e.ctx, admin, clerk.ID, service.RoleInput{Name: "Clerk", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	require.Equal(t, 2, updated.Version)
	require.Equal(t, []string{"order:read"}, updated.Permissions)

	require.Equal(t, map[string]string{"order:read": "1"}, e.hash(t, redisview.RoleKey(id, clerk.ID)))

	roles, err := e.roles.List(e.ctx, admin)
	require.NoError(t, err)
	require.Len(t, roles, 2)
	var adminRole service.Role
	for _, r := range roles {
		if r.Protected {
			adminRole = r
		}
	}
	_, err = e.roles.Update(e.ctx, admin, adminRole.ID, service.RoleInput{Name: "Boss"})
	requireStatus(t, err, service.KindPrecondition, "protected_role")
	requireStatus(t, e.roles.Delete(e.ctx, admin, adminRole.ID), service.KindPrecondition, "protected_role")

	require.NoError(t, e.roles.Delete(e.ctx, admin, clerk.ID))
	_, err = e.roles.Get(e.ctx, admin, clerk.ID)
	requireStatus(t, err, service.KindNotFound, "")
	require.Empty(t, e.hash(t, redisview.RoleKey(id, clerk.ID)))
}

func TestRoles_TenantIsolation(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, acme := e.company(t, "acme")
	_, globex := e.company(t, "globex")
	role, err := e.roles.Create(e.ctx, acme, service.RoleInput{Name: "Clerk", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	_, err = e.roles.Get(e.ctx, globex, role.ID)
	requireStatus(t, err, service.KindNotFound, "")
	_, err = e.roles.Update(e.ctx, globex, role.ID, service.RoleInput{Name: "Mine"})
	requireStatus(t, err, service.KindNotFound, "")
	requireStatus(t, e.members.SetRoles(e.ctx, globex, globex.Sub, []string{role.ID}), service.KindInvalid, "unknown_role")
	requireStatus(t, e.members.SetRoles(e.ctx, globex, acme.Sub, nil), service.KindNotFound, "")

	// A caller whose headers name a company they don't belong to gets nothing.
	_, err = e.roles.List(e.ctx, service.Caller{Sub: globex.Sub, CompanyID: acme.CompanyID})
	requireStatus(t, err, service.KindForbidden, "not_a_member")
}

// A clerk with member:manage but not order:cancel cannot hand out order:cancel, the admin role,
// or take roles away from someone more powerful.
func TestEscalation(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, err := e.catalogue.ApplyManifest(e.ctx, "authz", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "role:manage"}, {Key: "member:manage"}},
	})
	require.NoError(t, err)
	id, admin := e.company(t, "acme")

	lead, err := e.roles.Create(e.ctx, admin, service.RoleInput{Name: "Lead", Permissions: []string{"order:read", "role:manage", "member:manage"}})
	require.NoError(t, err)
	cancel, err := e.roles.Create(e.ctx, admin, service.RoleInput{Name: "Canceller", Permissions: []string{"order:cancel"}})
	require.NoError(t, err)
	reader, err := e.roles.Create(e.ctx, admin, service.RoleInput{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	inv, err := e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000001", RoleIDs: []string{lead.ID}})
	require.NoError(t, err)
	require.NoError(t, e.invitations.Accept(e.ctx, inv.ID, "lead-1"))
	leadCaller := service.Caller{Sub: "lead-1", CompanyID: id}

	_, err = e.roles.Create(e.ctx, leadCaller, service.RoleInput{Name: "Sneaky", Permissions: []string{"order:cancel"}})
	requireStatus(t, err, service.KindForbidden, "escalation")
	_, err = e.roles.Update(e.ctx, leadCaller, cancel.ID, service.RoleInput{Name: "Canceller", Permissions: []string{"order:read"}})
	requireStatus(t, err, service.KindForbidden, "escalation")
	requireStatus(t, e.members.SetRoles(e.ctx, leadCaller, "lead-1", []string{lead.ID, cancel.ID}), service.KindForbidden, "escalation")
	requireStatus(t, e.members.Remove(e.ctx, leadCaller, admin.Sub), service.KindForbidden, "escalation")
	_, err = e.invitations.Create(e.ctx, leadCaller, service.InvitationInput{Phone: "+8801711000002", RoleIDs: []string{cancel.ID}})
	requireStatus(t, err, service.KindForbidden, "escalation")

	// Within their own permissions it works.
	_, err = e.roles.Create(e.ctx, leadCaller, service.RoleInput{Name: "Viewer", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	require.NoError(t, e.members.SetRoles(e.ctx, leadCaller, "lead-1", []string{lead.ID, reader.ID}))
}

func TestLastAdmin(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	claims, err := e.companies.Claims(e.ctx, admin.Sub)
	require.NoError(t, err)
	adminRole := claims.Roles[0].ID

	requireStatus(t, e.members.SetRoles(e.ctx, admin, admin.Sub, nil), service.KindPrecondition, "last_admin")
	requireStatus(t, e.members.Remove(e.ctx, admin, admin.Sub), service.KindPrecondition, "last_admin")

	inv, err := e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000003", RoleIDs: []string{adminRole}})
	require.NoError(t, err)
	require.NoError(t, e.invitations.Accept(e.ctx, inv.ID, "admin-2"))

	// With a second admin, the first may step down and then be removed.
	require.NoError(t, e.members.SetRoles(e.ctx, admin, admin.Sub, nil))
	second := service.Caller{Sub: "admin-2", CompanyID: id}
	require.NoError(t, e.members.Remove(e.ctx, second, admin.Sub))
	_, err = e.companies.Claims(e.ctx, admin.Sub)
	requireStatus(t, err, service.KindNotFound, "not_a_member")

	members, err := e.members.List(e.ctx, second)
	require.NoError(t, err)
	require.Len(t, members, 1)
	require.Equal(t, []string{adminRole}, members[0].RoleIDs)
}

func TestInvitations(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	_, other := e.company(t, "globex")
	reader, err := e.roles.Create(e.ctx, admin, service.RoleInput{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	_, err = e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "01711000001"})
	requireStatus(t, err, service.KindInvalid, "invalid_phone")

	// Someone who already belongs to a company (any company) cannot be invited.
	e.idp.byPhone["+8801711000009"] = other.Sub
	_, err = e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000009"})
	requireStatus(t, err, service.KindConflict, "cannot_invite")

	inv, err := e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000001", RoleIDs: []string{reader.ID}})
	require.NoError(t, err)
	require.Equal(t, "pending", inv.Status)
	require.Equal(t, "acme", inv.CompanyName)
	require.Len(t, e.idp.sent, 1)
	require.Equal(t, inv.ID, e.idp.sent[0].ID)

	// Re-inviting the same phone replaces the pending invitation.
	inv2, err := e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000001", RoleIDs: []string{reader.ID}})
	require.NoError(t, err)
	old, err := e.invitations.Get(e.ctx, inv.ID)
	require.NoError(t, err)
	require.Equal(t, "expired", old.Status)
	requireStatus(t, e.invitations.Accept(e.ctx, inv.ID, "staff-1"), service.KindPrecondition, "expired")

	require.NoError(t, e.invitations.Accept(e.ctx, inv2.ID, "staff-1"))
	claims, err := e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Equal(t, claims.AuthzVersion, e.version(t, "staff-1"))
	require.Equal(t, id, claims.CompanyID)
	require.Equal(t, "Reader", claims.Roles[0].Name)

	requireStatus(t, e.invitations.Accept(e.ctx, inv2.ID, "staff-1"), service.KindConflict, "already_accepted")

	// Accepting as someone who already belongs to a company fails.
	inv3, err := e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000002"})
	require.NoError(t, err)
	requireStatus(t, e.invitations.Accept(e.ctx, inv3.ID, other.Sub), service.KindConflict, "already_member")

	// An invitation that could not be delivered is not kept.
	e.idp.sendErr = errors.New("down")
	_, err = e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000004"})
	requireStatus(t, err, service.KindUnavailable, "idp_unavailable")
	list, err := e.invitations.List(e.ctx, admin)
	require.NoError(t, err)
	require.Len(t, list, 3)
}

func TestInvitation_Expiry(t *testing.T) {
	e := newService(t)
	_, admin := e.company(t, "acme")
	inv, err := e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000001"})
	require.NoError(t, err)
	e.invitations.SetClock(func() time.Time { return time.Now().Add(8 * 24 * time.Hour) })
	requireStatus(t, e.invitations.Accept(e.ctx, inv.ID, "late"), service.KindPrecondition, "expired")
}

// A member's version changes with their roles, is never reused, and leaves the view with them.
func TestAuthzVersion(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, admin := e.company(t, "acme")
	reader, err := e.roles.Create(e.ctx, admin, service.RoleInput{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	inv, err := e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000001"})
	require.NoError(t, err)
	require.NoError(t, e.invitations.Accept(e.ctx, inv.ID, "staff-1"))
	v1 := e.version(t, "staff-1")

	// A role edit applies through the role's key: no version change, no refresh needed.
	_, err = e.roles.Update(e.ctx, admin, reader.ID, service.RoleInput{Name: "Reader", Permissions: []string{"order:create"}})
	require.NoError(t, err)
	require.Equal(t, v1, e.version(t, "staff-1"))

	// An assignment change does: the old token is stale.
	require.NoError(t, e.members.SetRoles(e.ctx, admin, "staff-1", []string{reader.ID}))
	v2 := e.version(t, "staff-1")
	require.Greater(t, v2, v1)
	claims, err := e.companies.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Equal(t, v2, claims.AuthzVersion)

	// Removed: no version at all. Invited back, a version never seen before.
	require.NoError(t, e.members.Remove(e.ctx, admin, "staff-1"))
	require.Zero(t, e.version(t, "staff-1"))
	inv, err = e.invitations.Create(e.ctx, admin, service.InvitationInput{Phone: "+8801711000002"})
	require.NoError(t, err)
	require.NoError(t, e.invitations.Accept(e.ctx, inv.ID, "staff-1"))
	require.Greater(t, e.version(t, "staff-1"), v2)
}

// Rebuild rewrites the whole view from Postgres and deletes keys it no longer has.
func TestRebuild(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	require.NoError(t, e.rdb.FlushAll(e.ctx).Err())
	require.NoError(t, e.rdb.Set(e.ctx, redisview.UserVersionKey("ghost"), 7, 0).Err())
	require.NoError(t, e.rdb.Set(e.ctx, "other:key", 1, 0).Err())

	require.NoError(t, e.view.Rebuild(e.ctx))
	require.Len(t, e.hash(t, redisview.RoutesKey), 4)
	require.Equal(t, "active", e.hash(t, redisview.CompanyKey(id))["status"])
	claims, err := e.companies.Claims(e.ctx, admin.Sub)
	require.NoError(t, err)
	require.Equal(t, claims.AuthzVersion, e.version(t, admin.Sub))
	require.Equal(t, map[string]string{service.AllPermission: "1"}, e.hash(t, redisview.RoleKey(id, claims.Roles[0].ID)))
	require.Zero(t, e.version(t, "ghost"), "an orphan key is deleted")
	n, err := e.rdb.Exists(e.ctx, "other:key").Result()
	require.NoError(t, err)
	require.EqualValues(t, 1, n, "keys outside authz: are not Authz's")
}
