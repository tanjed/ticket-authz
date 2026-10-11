package member

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiff(t *testing.T) {
	added, removed := diff([]string{"a", "b"}, []string{"b", "c"})
	require.Equal(t, []string{"c"}, added)
	require.Equal(t, []string{"a"}, removed)
}
