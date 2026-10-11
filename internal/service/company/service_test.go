package company

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidCompanyName(t *testing.T) {
	name, err := validCompanyName("  Acme ")
	require.NoError(t, err)
	require.Equal(t, "Acme", name)
	_, err = validCompanyName("  ")
	require.Error(t, err)
}
