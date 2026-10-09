// Package redisview stores the gateway view (service.GatewayView) in Redis: Authz writes the master, the
// gateway reads a replica. The key layout is the contract with the gateway (../APISIX); see
// docs/superpowers/specs/2026-10-06-redis-gateway-view-design.md.
package redisview

import (
	"context"
	"strconv"

	"github.com/redis/go-redis/v9"

	"github.com/tanjed/bus2/authz/internal/service"
)

// The keys. Every key Authz owns starts with Prefix: Replace deletes the ones it does not list.
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

var _ service.GatewayView = (*Redis)(nil)

// Redis is the gateway view on a Redis master. Each key is replaced whole in one MULTI (DEL, then
// write), so a reader never sees half of it.
type Redis struct {
	C redis.UniversalClient
}

func (r *Redis) PutRoutes(ctx context.Context, routes map[string]string) error {
	return r.tx(ctx, func(p redis.Pipeliner) { putHash(ctx, p, RoutesKey, routes) })
}

func (r *Redis) PutConsumer(ctx context.Context, permissions []string) error {
	return r.tx(ctx, func(p redis.Pipeliner) { putSet(ctx, p, ConsumerKey, permissions) })
}

func (r *Redis) PutCompany(ctx context.Context, companyID, status string) error {
	return r.tx(ctx, func(p redis.Pipeliner) { putHash(ctx, p, CompanyKey(companyID), map[string]string{"status": status}) })
}

func (r *Redis) PutRole(ctx context.Context, role service.RoleView) error {
	return r.tx(ctx, func(p redis.Pipeliner) { putRole(ctx, p, role) })
}

func (r *Redis) DeleteRole(ctx context.Context, companyID, roleID string) error {
	return r.C.Del(ctx, RoleKey(companyID, roleID)).Err()
}

func (r *Redis) PutUserVersion(ctx context.Context, sub string, version int64) error {
	return r.C.Set(ctx, UserVersionKey(sub), version, 0).Err()
}

func (r *Redis) DeleteUser(ctx context.Context, sub string) error {
	return r.C.Del(ctx, UserVersionKey(sub)).Err()
}

// Replace writes the whole view and deletes every other key under Prefix, in one MULTI.
func (r *Redis) Replace(ctx context.Context, s service.Snapshot) error {
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
func putRole(ctx context.Context, p redis.Pipeliner, role service.RoleView) {
	fields := make(map[string]string, len(role.Permissions))
	for _, k := range role.Permissions {
		fields[k] = "1"
	}
	putHash(ctx, p, RoleKey(role.CompanyID, role.RoleID), fields)
}
