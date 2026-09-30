package catalogue

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecode_Valid(t *testing.T) {
	m, err := Decode(strings.NewReader(`{
		"permissions": [{"key": "order:create", "description": "x", "consumer": true}, {"key": "order:cancel"}],
		"routes": [{"name": "order.create", "permission": "order:create"}, {"name": "order.health", "public": true}]
	}`))
	require.NoError(t, err)
	require.Len(t, m.Permissions, 2)
	require.True(t, m.Permissions[0].Consumer)
	require.True(t, m.Routes[1].Public)
}

func TestDecode_Invalid(t *testing.T) {
	cases := map[string]string{
		"versioned key":      `{"permissions":[{"key":"order:v1:create"}]}`,
		"uppercase key":      `{"permissions":[{"key":"Order:create"}]}`,
		"no action":          `{"permissions":[{"key":"order"}]}`,
		"duplicate key":      `{"permissions":[{"key":"a:b"},{"key":"a:b"}]}`,
		"unknown field":      `{"permissions":[{"key":"a:b","consumers":true}]}`,
		"route both":         `{"permissions":[{"key":"a:b"}],"routes":[{"name":"r","permission":"a:b","public":true}]}`,
		"route neither":      `{"routes":[{"name":"r"}]}`,
		"route foreign perm": `{"permissions":[{"key":"a:b"}],"routes":[{"name":"r","permission":"a:c"}]}`,
		"duplicate route":    `{"routes":[{"name":"r","public":true},{"name":"r","public":true}]}`,
		"bad route name":     `{"routes":[{"name":"Bad Name","public":true}]}`,
		"not json":           `nope`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(body))
			require.Error(t, err)
		})
	}
}

func TestValidService(t *testing.T) {
	require.True(t, ValidService("order"))
	require.True(t, ValidService("ticket-search"))
	require.False(t, ValidService("Order"))
	require.False(t, ValidService(""))
	require.False(t, ValidService("a/b"))
}
