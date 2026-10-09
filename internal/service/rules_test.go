package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The pure rules, without storage.

func TestPowerCovers(t *testing.T) {
	clerk := Power{Perms: map[string]bool{"order:read": true, "order:create": true}}
	require.True(t, clerk.Covers(Role{Permissions: []string{"order:read"}}))
	require.True(t, clerk.Covers(Role{}), "an empty role is always grantable")
	require.False(t, clerk.Covers(Role{Permissions: []string{"order:read", "order:cancel"}}), "one missing permission is escalation")
	require.False(t, clerk.Covers(Role{GrantsAll: true}), "only a grants_all holder can grant everything")

	admin := Power{All: true}
	require.True(t, admin.Covers(Role{GrantsAll: true}))
	require.True(t, admin.Covers(Role{Permissions: []string{"anything:else"}}))

	require.False(t, clerk.coversAll(map[string]Role{"a": {Permissions: []string{"order:read"}}, "b": {GrantsAll: true}}))
}

func TestRoleInputNormalized(t *testing.T) {
	in, err := RoleInput{Name: "  Clerk ", Permissions: []string{"order:read", "order:create", "order:read"}}.normalized()
	require.NoError(t, err)
	require.Equal(t, RoleInput{Name: "Clerk", Permissions: []string{"order:create", "order:read"}}, in)

	_, err = RoleInput{Name: "   "}.normalized()
	requireCode(t, err, "invalid_name")
	_, err = RoleInput{Name: "Clerk", Permissions: []string{"Not A Key"}}.normalized()
	requireCode(t, err, "unknown_permission")
}

func TestValidators(t *testing.T) {
	require.NoError(t, validPhone("+8801712345678"))
	requireCode(t, validPhone("01712345678"), "invalid_phone")
	requireCode(t, validSubject("", "sub"), "invalid_subject")
	name, err := validCompanyName("  Acme ")
	require.NoError(t, err)
	require.Equal(t, "Acme", name)
}

func TestInvitationStatus(t *testing.T) {
	now := time.Now()
	accepted := now.Add(-time.Hour)
	require.Equal(t, InvitationPending, status(Invitation{ExpiresAt: now.Add(time.Hour)}, now))
	require.Equal(t, InvitationExpired, status(Invitation{ExpiresAt: now}, now), "expiry is exclusive")
	require.Equal(t, InvitationAccepted, status(Invitation{ExpiresAt: now.Add(-time.Hour), AcceptedAt: &accepted}, now))
}

func TestDiff(t *testing.T) {
	added, removed := diff([]string{"a", "b"}, []string{"b", "c"})
	require.Equal(t, []string{"c"}, added)
	require.Equal(t, []string{"a"}, removed)
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	e, ok := AsError(err)
	require.True(t, ok, "want domain error, got %v", err)
	require.Equal(t, code, e.Code)
}
