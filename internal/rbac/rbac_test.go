package rbac_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/rbac"
)

func TestApplyManifest_IdempotentAndBumpsOnlyOnChange(t *testing.T) {
	e := newService(t)
	e.seed(t)
	cat := e.revision(t, rbac.BundleCatalogue)

	e.seed(t) // same manifest again
	require.Equal(t, cat, e.revision(t, rbac.BundleCatalogue), "a no-op re-seed must not bump")

	res, err := e.svc.ApplyManifest(e.ctx, "order", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "order:create", Consumer: true}},
		Routes:      []catalogue.Route{{Name: "order.create", Permission: "order:create"}},
	})
	require.NoError(t, err)
	require.True(t, res.Changed)
	require.Greater(t, e.revision(t, rbac.BundleCatalogue), cat)

	snap, _, err := e.svc.BundleSnapshot(e.ctx, rbac.BundleCatalogue)
	require.NoError(t, err)
	require.Equal(t, map[string]rbac.RouteRule{"order.create": {Permission: "order:create"}}, snap.Routes,
		"dropped routes are deprecated and leave the bundle")

	perms, err := e.svc.Permissions(e.ctx)
	require.NoError(t, err)
	require.Len(t, perms, 1)

	e.seed(t) // listing them again restores them
	snap, _, err = e.svc.BundleSnapshot(e.ctx, rbac.BundleCatalogue)
	require.NoError(t, err)
	require.Len(t, snap.Routes, 4)
	require.True(t, snap.Routes["order.health"].Public)
}

func TestApplyManifest_OwnershipConflict(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, err := e.svc.ApplyManifest(e.ctx, "billing", catalogue.Manifest{Permissions: []catalogue.Permission{{Key: "order:create"}}})
	requireStatus(t, err, rbac.KindConflict, "owned_elsewhere")
	_, err = e.svc.ApplyManifest(e.ctx, "billing", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "invoice:read"}},
		Routes:      []catalogue.Route{{Name: "order.create", Permission: "invoice:read"}},
	})
	requireStatus(t, err, rbac.KindConflict, "owned_elsewhere")
	_, err = e.svc.ApplyManifest(e.ctx, "Bad/Name", catalogue.Manifest{})
	requireStatus(t, err, rbac.KindInvalid, "invalid_service")
}

func TestConsumerBundle(t *testing.T) {
	e := newService(t)
	e.seed(t)
	snap, ok, err := e.svc.BundleSnapshot(e.ctx, rbac.BundleConsumer)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, map[string]bool{"order:create": true, "order:read": true}, snap.Consumer)
}

func TestCreateCompany_AndClaims(t *testing.T) {
	e := newService(t)
	disc := e.revision(t, rbac.BundleDiscovery)
	id, admin := e.company(t, "acme")
	require.Greater(t, e.revision(t, rbac.BundleDiscovery), disc)

	claims, err := e.svc.Claims(e.ctx, admin.Sub)
	require.NoError(t, err)
	require.Equal(t, id, claims.CompanyID)
	require.Len(t, claims.Roles, 1)
	require.Equal(t, rbac.AdminRoleName, claims.Roles[0].Name)

	// Idempotent per subject.
	again, created, err := e.svc.CreateCompany(e.ctx, "other name", admin.Sub)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, id, again)

	_, err = e.svc.Claims(e.ctx, "nobody")
	requireStatus(t, err, rbac.KindNotFound, "not_a_member")

	_, _, err = e.svc.CreateCompany(e.ctx, "  ", "x")
	requireStatus(t, err, rbac.KindInvalid, "invalid_name")

	snap, ok, err := e.svc.BundleSnapshot(e.ctx, rbac.CompanyBundle(id))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "active", snap.Company.Status)
	require.True(t, snap.Company.Roles[claims.Roles[0].ID].GrantsAll)

	snap, _, err = e.svc.BundleSnapshot(e.ctx, rbac.BundleDiscovery)
	require.NoError(t, err)
	require.Equal(t, []string{id}, snap.CompanyIDs)
	require.Equal(t, []string{"COMPANY_REGISTERED"}, e.ev.names())
}

func TestSuspendedCompany(t *testing.T) {
	e := newService(t)
	id, admin := e.company(t, "acme")
	rev := e.revision(t, rbac.CompanyBundle(id))
	require.NoError(t, e.svc.SetCompanyStatus(e.ctx, id, "suspended"))
	require.Greater(t, e.revision(t, rbac.CompanyBundle(id)), rev)
	_, err := e.svc.Claims(e.ctx, admin.Sub)
	requireStatus(t, err, rbac.KindForbidden, "company_suspended")
	snap, _, err := e.svc.BundleSnapshot(e.ctx, rbac.CompanyBundle(id))
	require.NoError(t, err)
	require.Equal(t, "suspended", snap.Company.Status)

	require.NoError(t, e.svc.SetCompanyStatus(e.ctx, id, "active"))
	_, err = e.svc.Claims(e.ctx, admin.Sub)
	require.NoError(t, err)
	requireStatus(t, e.svc.SetCompanyStatus(e.ctx, "5f1d3c1e-0000-4000-8000-000000000000", "active"), rbac.KindNotFound, "")
}

func TestRoles_CRUDAndBundle(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	rev := e.revision(t, rbac.CompanyBundle(id))

	clerk, err := e.svc.CreateRole(e.ctx, admin, rbac.RoleInput{Name: " Clerk ", Permissions: []string{"order:read", "order:create", "order:read"}})
	require.NoError(t, err)
	require.Equal(t, "Clerk", clerk.Name)
	require.Equal(t, []string{"order:create", "order:read"}, clerk.Permissions)
	require.Equal(t, 1, clerk.Version)
	require.Greater(t, e.revision(t, rbac.CompanyBundle(id)), rev)

	_, err = e.svc.CreateRole(e.ctx, admin, rbac.RoleInput{Name: "clerk"})
	requireStatus(t, err, rbac.KindConflict, "name_taken")
	_, err = e.svc.CreateRole(e.ctx, admin, rbac.RoleInput{Name: "X", Permissions: []string{"order:fly"}})
	requireStatus(t, err, rbac.KindInvalid, "unknown_permission")

	updated, err := e.svc.UpdateRole(e.ctx, admin, clerk.ID, rbac.RoleInput{Name: "Clerk", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	require.Equal(t, 2, updated.Version)
	require.Equal(t, []string{"order:read"}, updated.Permissions)

	snap, _, err := e.svc.BundleSnapshot(e.ctx, rbac.CompanyBundle(id))
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"order:read": true}, snap.Company.Roles[clerk.ID].Permissions)

	roles, err := e.svc.ListRoles(e.ctx, admin)
	require.NoError(t, err)
	require.Len(t, roles, 2)
	var adminRole rbac.Role
	for _, r := range roles {
		if r.Protected {
			adminRole = r
		}
	}
	_, err = e.svc.UpdateRole(e.ctx, admin, adminRole.ID, rbac.RoleInput{Name: "Boss"})
	requireStatus(t, err, rbac.KindPrecondition, "protected_role")
	requireStatus(t, e.svc.DeleteRole(e.ctx, admin, adminRole.ID), rbac.KindPrecondition, "protected_role")

	require.NoError(t, e.svc.DeleteRole(e.ctx, admin, clerk.ID))
	_, err = e.svc.GetRole(e.ctx, admin, clerk.ID)
	requireStatus(t, err, rbac.KindNotFound, "")
}

func TestRoles_TenantIsolation(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, acme := e.company(t, "acme")
	_, globex := e.company(t, "globex")
	role, err := e.svc.CreateRole(e.ctx, acme, rbac.RoleInput{Name: "Clerk", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	_, err = e.svc.GetRole(e.ctx, globex, role.ID)
	requireStatus(t, err, rbac.KindNotFound, "")
	_, err = e.svc.UpdateRole(e.ctx, globex, role.ID, rbac.RoleInput{Name: "Mine"})
	requireStatus(t, err, rbac.KindNotFound, "")
	requireStatus(t, e.svc.SetMemberRoles(e.ctx, globex, globex.Sub, []string{role.ID}), rbac.KindInvalid, "unknown_role")
	requireStatus(t, e.svc.SetMemberRoles(e.ctx, globex, acme.Sub, nil), rbac.KindNotFound, "")

	// A caller whose headers name a company they don't belong to gets nothing.
	_, err = e.svc.ListRoles(e.ctx, rbac.Caller{Sub: globex.Sub, CompanyID: acme.CompanyID})
	requireStatus(t, err, rbac.KindForbidden, "not_a_member")
}

// A clerk with member:manage but not order:cancel cannot hand out order:cancel, the admin role,
// or take roles away from someone more powerful.
func TestEscalation(t *testing.T) {
	e := newService(t)
	e.seed(t)
	_, err := e.svc.ApplyManifest(e.ctx, "authz", catalogue.Manifest{
		Permissions: []catalogue.Permission{{Key: "role:manage"}, {Key: "member:manage"}},
	})
	require.NoError(t, err)
	id, admin := e.company(t, "acme")

	lead, err := e.svc.CreateRole(e.ctx, admin, rbac.RoleInput{Name: "Lead", Permissions: []string{"order:read", "role:manage", "member:manage"}})
	require.NoError(t, err)
	cancel, err := e.svc.CreateRole(e.ctx, admin, rbac.RoleInput{Name: "Canceller", Permissions: []string{"order:cancel"}})
	require.NoError(t, err)
	reader, err := e.svc.CreateRole(e.ctx, admin, rbac.RoleInput{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	inv, err := e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000001", RoleIDs: []string{lead.ID}})
	require.NoError(t, err)
	require.NoError(t, e.svc.AcceptInvitation(e.ctx, inv.ID, "lead-1"))
	leadCaller := rbac.Caller{Sub: "lead-1", CompanyID: id}

	_, err = e.svc.CreateRole(e.ctx, leadCaller, rbac.RoleInput{Name: "Sneaky", Permissions: []string{"order:cancel"}})
	requireStatus(t, err, rbac.KindForbidden, "escalation")
	_, err = e.svc.UpdateRole(e.ctx, leadCaller, cancel.ID, rbac.RoleInput{Name: "Canceller", Permissions: []string{"order:read"}})
	requireStatus(t, err, rbac.KindForbidden, "escalation")
	requireStatus(t, e.svc.SetMemberRoles(e.ctx, leadCaller, "lead-1", []string{lead.ID, cancel.ID}), rbac.KindForbidden, "escalation")
	requireStatus(t, e.svc.RemoveMember(e.ctx, leadCaller, admin.Sub), rbac.KindForbidden, "escalation")
	_, err = e.svc.CreateInvitation(e.ctx, leadCaller, rbac.InvitationInput{Phone: "+8801711000002", RoleIDs: []string{cancel.ID}})
	requireStatus(t, err, rbac.KindForbidden, "escalation")

	// Within their own permissions it works.
	_, err = e.svc.CreateRole(e.ctx, leadCaller, rbac.RoleInput{Name: "Viewer", Permissions: []string{"order:read"}})
	require.NoError(t, err)
	require.NoError(t, e.svc.SetMemberRoles(e.ctx, leadCaller, "lead-1", []string{lead.ID, reader.ID}))
}

func TestLastAdmin(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	claims, err := e.svc.Claims(e.ctx, admin.Sub)
	require.NoError(t, err)
	adminRole := claims.Roles[0].ID

	requireStatus(t, e.svc.SetMemberRoles(e.ctx, admin, admin.Sub, nil), rbac.KindPrecondition, "last_admin")
	requireStatus(t, e.svc.RemoveMember(e.ctx, admin, admin.Sub), rbac.KindPrecondition, "last_admin")

	inv, err := e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000003", RoleIDs: []string{adminRole}})
	require.NoError(t, err)
	require.NoError(t, e.svc.AcceptInvitation(e.ctx, inv.ID, "admin-2"))

	// With a second admin, the first may step down and then be removed.
	require.NoError(t, e.svc.SetMemberRoles(e.ctx, admin, admin.Sub, nil))
	second := rbac.Caller{Sub: "admin-2", CompanyID: id}
	require.NoError(t, e.svc.RemoveMember(e.ctx, second, admin.Sub))
	_, err = e.svc.Claims(e.ctx, admin.Sub)
	requireStatus(t, err, rbac.KindNotFound, "not_a_member")

	members, err := e.svc.ListMembers(e.ctx, second)
	require.NoError(t, err)
	require.Len(t, members, 1)
	require.Equal(t, []string{adminRole}, members[0].RoleIDs)
}

func TestInvitations(t *testing.T) {
	e := newService(t)
	e.seed(t)
	id, admin := e.company(t, "acme")
	_, other := e.company(t, "globex")
	reader, err := e.svc.CreateRole(e.ctx, admin, rbac.RoleInput{Name: "Reader", Permissions: []string{"order:read"}})
	require.NoError(t, err)

	_, err = e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "01711000001"})
	requireStatus(t, err, rbac.KindInvalid, "invalid_phone")

	// Someone who already belongs to a company (any company) cannot be invited.
	e.idp.byPhone["+8801711000009"] = other.Sub
	_, err = e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000009"})
	requireStatus(t, err, rbac.KindConflict, "cannot_invite")

	inv, err := e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000001", RoleIDs: []string{reader.ID}})
	require.NoError(t, err)
	require.Equal(t, "pending", inv.Status)
	require.Equal(t, "acme", inv.CompanyName)
	require.Len(t, e.idp.sent, 1)
	require.Equal(t, inv.ID, e.idp.sent[0].ID)

	// Re-inviting the same phone replaces the pending invitation.
	inv2, err := e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000001", RoleIDs: []string{reader.ID}})
	require.NoError(t, err)
	old, err := e.svc.GetInvitation(e.ctx, inv.ID)
	require.NoError(t, err)
	require.Equal(t, "expired", old.Status)
	requireStatus(t, e.svc.AcceptInvitation(e.ctx, inv.ID, "staff-1"), rbac.KindPrecondition, "expired")

	rev := e.revision(t, rbac.CompanyBundle(id))
	require.NoError(t, e.svc.AcceptInvitation(e.ctx, inv2.ID, "staff-1"))
	require.Greater(t, e.revision(t, rbac.CompanyBundle(id)), rev)
	claims, err := e.svc.Claims(e.ctx, "staff-1")
	require.NoError(t, err)
	require.Equal(t, id, claims.CompanyID)
	require.Equal(t, "Reader", claims.Roles[0].Name)

	requireStatus(t, e.svc.AcceptInvitation(e.ctx, inv2.ID, "staff-1"), rbac.KindConflict, "already_accepted")

	// Accepting as someone who already belongs to a company fails.
	inv3, err := e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000002"})
	require.NoError(t, err)
	requireStatus(t, e.svc.AcceptInvitation(e.ctx, inv3.ID, other.Sub), rbac.KindConflict, "already_member")

	// An invitation that could not be delivered is not kept.
	e.idp.sendErr = errors.New("down")
	_, err = e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000004"})
	requireStatus(t, err, rbac.KindUnavailable, "idp_unavailable")
	list, err := e.svc.ListInvitations(e.ctx, admin)
	require.NoError(t, err)
	require.Len(t, list, 3)
}

func TestInvitation_Expiry(t *testing.T) {
	e := newService(t)
	_, admin := e.company(t, "acme")
	inv, err := e.svc.CreateInvitation(e.ctx, admin, rbac.InvitationInput{Phone: "+8801711000001"})
	require.NoError(t, err)
	e.svc.Now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
	requireStatus(t, e.svc.AcceptInvitation(e.ctx, inv.ID, "late"), rbac.KindPrecondition, "expired")
}
