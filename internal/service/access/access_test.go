package access

import (
	"testing"

	"github.com/stretchr/testify/require"

	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

func TestPowerCovers(t *testing.T) {
	clerk := Power{Perms: map[string]bool{"order:read": true, "order:create": true}}
	require.True(t, clerk.Covers(rolerepo.Role{Permissions: []string{"order:read"}}))
	require.True(t, clerk.Covers(rolerepo.Role{}), "an empty role is always grantable")
	require.False(t, clerk.Covers(rolerepo.Role{Permissions: []string{"order:read", "order:cancel"}}), "one missing permission is escalation")
	require.False(t, clerk.Covers(rolerepo.Role{GrantsAll: true}), "only a grants_all holder can grant everything")

	admin := Power{All: true}
	require.True(t, admin.Covers(rolerepo.Role{GrantsAll: true}))
	require.True(t, admin.Covers(rolerepo.Role{Permissions: []string{"anything:else"}}))

	require.False(t, clerk.CoversAll(map[string]rolerepo.Role{"a": {Permissions: []string{"order:read"}}, "b": {GrantsAll: true}}))
}
