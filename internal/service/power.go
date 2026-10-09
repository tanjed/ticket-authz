package service

import (
	"context"

	"github.com/google/uuid"
)

// Power is what a caller may hand out: everything (grants_all) or a set of permissions.
type Power struct {
	All   bool
	Perms map[string]bool
}

// Covers is the escalation rule (invariant 5): a role can be created, edited, deleted, assigned
// or taken away only by someone whose own permissions include all of the role's.
func (p Power) Covers(r Role) bool {
	if p.All {
		return true
	}
	if r.GrantsAll {
		return false
	}
	for _, k := range r.Permissions {
		if !p.Perms[k] {
			return false
		}
	}
	return true
}

// coversAll is Covers for every role.
func (p Power) coversAll(roles map[string]Role) bool {
	for _, r := range roles {
		if !p.Covers(r) {
			return false
		}
	}
	return true
}

// callerPower reads the caller's effective permissions fresh from the database (never from the
// token) and confirms they still belong to the company the gateway named.
func callerPower(ctx context.Context, members MemberRepo, c Caller) (Power, error) {
	if c.Sub == "" || uuid.Validate(c.CompanyID) != nil {
		return Power{}, notAMember()
	}
	ok, err := members.IsMember(ctx, c.Sub, c.CompanyID)
	if err != nil {
		return Power{}, err
	}
	if !ok {
		return Power{}, notAMember()
	}
	all, keys, err := members.Grants(ctx, c.Sub)
	if err != nil {
		return Power{}, err
	}
	p := Power{All: all, Perms: make(map[string]bool, len(keys))}
	for _, k := range keys {
		p.Perms[k] = true
	}
	return p, nil
}
