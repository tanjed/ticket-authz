package role

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/apperror"
)

func TestNormalized(t *testing.T) {
	in, err := normalized(Input{Name: "  Clerk ", Permissions: []string{"order:read", "order:create", "order:read"}})
	require.NoError(t, err)
	require.Equal(t, Input{Name: "Clerk", Permissions: []string{"order:create", "order:read"}}, in)

	_, err = normalized(Input{Name: "   "})
	requireCode(t, err, "invalid_name")
	_, err = normalized(Input{Name: "Clerk", Permissions: []string{"Not A Key"}})
	requireCode(t, err, "unknown_permission")
}

func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	e, ok := apperror.As(err)
	require.True(t, ok, "want domain error, got %v", err)
	require.Equal(t, code, e.Code)
}

func TestNormalized_LandingPath(t *testing.T) {
	for _, ok := range []string{"", "/", "/buses", "/buses/layouts", "/a-b_c.d~e"} {
		_, err := normalized(Input{Name: "R", LandingPath: ok})
		require.NoError(t, err, ok)
	}
	long := "/" + string(make([]byte, 0))
	for i := 0; i < 200; i++ {
		long += "a"
	}
	for _, bad := range []string{"buses", "//evil.com", "/a//b", "https://x.y", "/a b", "/a?x=1", "/a#b", long} {
		_, err := normalized(Input{Name: "R", LandingPath: bad})
		requireCode(t, err, "invalid_landing_path")
	}
}
