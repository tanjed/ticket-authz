package user

import userrepo "github.com/tanjed/bus2/authz/internal/repository/userrole"

// AdminRoleName is the protected role every company starts with.
const AdminRoleName = "Admin"

// UserRoles is a user and the ids of the roles they hold.
type UserRoles = userrepo.UserRoles

// Me is a caller's own access.
type Me struct {
	UserID      string
	CompanyID   string
	Permissions []string
	Roles       []MeRole
}

// MeRole is a role the caller holds.
type MeRole struct {
	ID, Name, LandingPath string
}
