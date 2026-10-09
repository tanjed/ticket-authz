package redisview

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// A role without permissions has no key, and a Put replaces the key whole.
func TestPutRole(t *testing.T) {
	ctx := context.Background()
	c := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	r := &Redis{C: c}
	key := RoleKey("c1", "r1")

	require.NoError(t, r.PutRole(ctx, rbac.RoleView{CompanyID: "c1", RoleID: "r1", Permissions: []string{"a:b", "c:d"}}))
	require.NoError(t, r.PutRole(ctx, rbac.RoleView{CompanyID: "c1", RoleID: "r1", Permissions: []string{"a:b"}}))
	require.Equal(t, map[string]string{"a:b": "1"}, c.HGetAll(ctx, key).Val())

	require.NoError(t, r.PutRole(ctx, rbac.RoleView{CompanyID: "c1", RoleID: "r1"}))
	require.Zero(t, c.Exists(ctx, key).Val())
}

// The readiness probe fails while Redis is down.
func TestProbe(t *testing.T) {
	m := miniredis.RunT(t)
	p := probe(redis.NewClient(&redis.Options{Addr: m.Addr(), MaxRetries: -1}))
	require.NoError(t, p.Check(context.Background()))
	m.Close()
	require.Error(t, p.Check(context.Background()))
}
