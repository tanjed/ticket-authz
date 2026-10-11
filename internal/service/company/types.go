package company

import memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"

// AdminRoleName is the protected role every company starts with.
const AdminRoleName = "Admin"

// Company statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// RoleRef is a role as it appears in the token.
type RoleRef = memberrepo.RoleRef

// Claims is what the IdP puts in a provider's access token. AuthzVersion is the member's
// authorization version: the gateway refuses the token once the view holds another.
type Claims struct {
	CompanyID    string    `json:"company_id"`
	Roles        []RoleRef `json:"roles"`
	AuthzVersion int64     `json:"authz_version"`
}
