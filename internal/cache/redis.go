package cache

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// The keys. Every key Authz owns starts with Prefix.
const (
	Prefix      = "authz:"
	RoutesKey   = Prefix + "routes"   // HASH route name -> permission key | "public"
	ConsumerKey = Prefix + "consumer" // SET permission keys
)

// CompanyKey is a company's HASH {status}.
func CompanyKey(companyID string) string { return Prefix + "company:" + companyID }

// RoleKey is a role's HASH permission -> "1" ("*" for grants_all).
func RoleKey(companyID, roleID string) string { return CompanyKey(companyID) + ":role:" + roleID }

// UserVersionKey is a member's authorization version (STRING).
func UserVersionKey(sub string) string { return Prefix + "user:" + sub + ":version" }

var _ Publisher = (*Redis)(nil)

// Redis publishes to a Redis master (the gateway reads a replica). Each key is replaced whole in one MULTI (DEL, then
// write), so a reader never sees half of it.
type Redis struct {
	C   redis.UniversalClient
	Log *slog.Logger
}

// publishTimeout bounds one write.
const publishTimeout = 5 * time.Second

// do runs one write, detached from the caller's cancellation and bounded, and logs a failure.
func (r *Redis) do(ctx context.Context, what string, fn func(ctx context.Context) error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), publishTimeout)
	defer cancel()
	if err := fn(ctx); err != nil {
		r.Log.ErrorContext(ctx, "redis publish failed; the gateway reads stale data until the next change", "what", what, "err", err)
	}
}

func (r *Redis) PutRoutes(ctx context.Context, routes map[string]string) {
	r.do(ctx, "routes", func(ctx context.Context) error {
		return r.tx(ctx, func(p redis.Pipeliner) { putHash(ctx, p, RoutesKey, routes) })
	})
}

func (r *Redis) PutConsumer(ctx context.Context, permissions []string) {
	r.do(ctx, "consumer", func(ctx context.Context) error {
		return r.tx(ctx, func(p redis.Pipeliner) { putSet(ctx, p, ConsumerKey, permissions) })
	})
}

func (r *Redis) PutCompany(ctx context.Context, companyID, status string) {
	r.do(ctx, "company", func(ctx context.Context) error {
		return r.tx(ctx, func(p redis.Pipeliner) { putHash(ctx, p, CompanyKey(companyID), map[string]string{"status": status}) })
	})
}

func (r *Redis) PutRole(ctx context.Context, role RoleView) {
	r.do(ctx, "role", func(ctx context.Context) error {
		return r.tx(ctx, func(p redis.Pipeliner) { putRole(ctx, p, role) })
	})
}

func (r *Redis) DeleteRole(ctx context.Context, companyID, roleID string) {
	r.do(ctx, "role", func(ctx context.Context) error { return r.C.Del(ctx, RoleKey(companyID, roleID)).Err() })
}

func (r *Redis) PutUserVersion(ctx context.Context, sub string, version int64) {
	r.do(ctx, "user version", func(ctx context.Context) error { return r.C.Set(ctx, UserVersionKey(sub), version, 0).Err() })
}

func (r *Redis) DeleteUser(ctx context.Context, sub string) {
	r.do(ctx, "user version", func(ctx context.Context) error { return r.C.Del(ctx, UserVersionKey(sub)).Err() })
}

func (r *Redis) Replace(ctx context.Context, s State) error {
	keep := map[string]bool{RoutesKey: true, ConsumerKey: true}
	for id := range s.Companies {
		keep[CompanyKey(id)] = true
	}
	for _, role := range s.Roles {
		keep[RoleKey(role.CompanyID, role.RoleID)] = true
	}
	for sub := range s.Users {
		keep[UserVersionKey(sub)] = true
	}
	var orphans []string
	iter := r.C.Scan(ctx, 0, Prefix+"*", 1000).Iterator()
	for iter.Next(ctx) {
		if !keep[iter.Val()] {
			orphans = append(orphans, iter.Val())
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return r.tx(ctx, func(p redis.Pipeliner) {
		if len(orphans) > 0 {
			p.Del(ctx, orphans...)
		}
		putHash(ctx, p, RoutesKey, s.Routes)
		putSet(ctx, p, ConsumerKey, s.Consumer)
		for id, status := range s.Companies {
			putHash(ctx, p, CompanyKey(id), map[string]string{"status": status})
		}
		for _, role := range s.Roles {
			putRole(ctx, p, role)
		}
		for sub, v := range s.Users {
			p.Set(ctx, UserVersionKey(sub), strconv.FormatInt(v, 10), 0)
		}
	})
}

func (r *Redis) tx(ctx context.Context, fn func(redis.Pipeliner)) error {
	_, err := r.C.TxPipelined(ctx, func(p redis.Pipeliner) error {
		fn(p)
		return nil
	})
	return err
}

func putHash(ctx context.Context, p redis.Pipeliner, key string, fields map[string]string) {
	p.Del(ctx, key)
	if len(fields) > 0 {
		p.HSet(ctx, key, fields)
	}
}

func putSet(ctx context.Context, p redis.Pipeliner, key string, members []string) {
	p.Del(ctx, key)
	if len(members) > 0 {
		args := make([]any, len(members))
		for i, m := range members {
			args[i] = m
		}
		p.SAdd(ctx, key, args...)
	}
}

// putRole: a role without permissions has no key (HEXISTS on a missing key is false).
func putRole(ctx context.Context, p redis.Pipeliner, role RoleView) {
	fields := make(map[string]string, len(role.Permissions))
	for _, k := range role.Permissions {
		fields[k] = "1"
	}
	putHash(ctx, p, RoleKey(role.CompanyID, role.RoleID), fields)
}
