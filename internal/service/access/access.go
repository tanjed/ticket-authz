// Package access is the escalation rule and the caller's power behind it, shared by the services
// that hand out roles (role, user).
package access

import (
	"context"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/apperror"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// Power is what a caller may hand out: everything (grants_all) or a set of permissions.
type Power struct {
	All   bool
	Perms map[string]bool
}

// Covers is the escalation rule (invariant 5): a role can be created, edited, deleted, assigned
// or taken away only by someone whose own permissions include all of the role's.
func (p Power) Covers(r rolerepo.Role) bool {
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

// CoversAll is Covers for every role.
func (p Power) CoversAll(roles map[string]rolerepo.Role) bool {
	for _, r := range roles {
		if !p.Covers(r) {
			return false
		}
	}
	return true
}

// CallerPower reads the caller's effective permissions fresh from the database (never from the
// token) and confirms they still hold roles in the company the gateway named.
func CallerPower(ctx context.Context, users userrepo.Repo, c Caller) (Power, error) {
	if c.UserID == "" || uuid.Validate(c.CompanyID) != nil {
		return Power{}, notAMember()
	}
	ok, err := users.IsMember(ctx, c.UserID, c.CompanyID)
	if err != nil {
		return Power{}, err
	}
	if !ok {
		return Power{}, notAMember()
	}
	all, keys, err := users.Grants(ctx, c.UserID, c.CompanyID)
	if err != nil {
		return Power{}, err
	}
	p := Power{All: all, Perms: make(map[string]bool, len(keys))}
	for _, k := range keys {
		p.Perms[k] = true
	}
	return p, nil
}

func notAMember() error {
	return apperror.Fail(apperror.KindForbidden, "not_a_member", "caller is not a member of this company")
}

// Caller is the gateway-verified user behind an admin API request (X-Bus-Subject, X-Bus-Company-Id).
type Caller struct {
	UserID    string
	CompanyID string
}

// ValidUserID checks a user id (the Kratos identity id, the token's sub) given in field.
func ValidUserID(id, field string) error {
	if id == "" || len(id) > 200 {
		return apperror.Fail(apperror.KindInvalid, "invalid_argument", "%s is required", field)
	}
	return nil
}
