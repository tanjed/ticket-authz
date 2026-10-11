package cache

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/health"
)

// Module provides the Redis client (the master, AUTHZ_REDIS_URL) and the Publisher on it, and
// contributes the "redis" health probe.
var Module = fx.Module("cache",
	fx.Provide(
		newClient,
		fx.Annotate(func(c redis.UniversalClient, log *slog.Logger) *Redis { return &Redis{C: c, Log: log} }, fx.As(new(Publisher))),
		fx.Annotate(probe, fx.ResultTags(health.ProbeGroup)),
	),
)

func newClient(lc fx.Lifecycle, cfg config.Config) (redis.UniversalClient, error) {
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("AUTHZ_REDIS_URL: %w", err)
	}
	c := redis.NewClient(opts)
	lc.Append(fx.StopHook(func(context.Context) error { return c.Close() }))
	return c, nil
}

// probe: the Redis master answers a ping.
func probe(c redis.UniversalClient) health.Probe {
	return health.Probe{Name: "redis", Check: func(ctx context.Context) error { return c.Ping(ctx).Err() }}
}
