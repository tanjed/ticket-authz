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
