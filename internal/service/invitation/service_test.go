package invitation

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/apperror"
)

func TestStatus(t *testing.T) {
	now := time.Now()
	accepted := now.Add(-time.Hour)
	require.Equal(t, Pending, status(Invitation{ExpiresAt: now.Add(time.Hour)}, now))
	require.Equal(t, Expired, status(Invitation{ExpiresAt: now}, now), "expiry is exclusive")
	require.Equal(t, Accepted, status(Invitation{ExpiresAt: now.Add(-time.Hour), AcceptedAt: &accepted}, now))
}

func TestValidPhone(t *testing.T) {
	require.NoError(t, validPhone("+8801712345678"))
	e, ok := apperror.As(validPhone("01712345678"))
	require.True(t, ok)
	require.Equal(t, "invalid_phone", e.Code)
}
