package role

import (
	"slices"

	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// Role is a role as stored.
type Role = rolerepo.Role

// Input is the body of role create and update.
type Input struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	LandingPath string   `json:"landing_path"`
}

// dedupe sorts ids and drops duplicates, in place.
func dedupe(ids []string) []string {
	slices.Sort(ids)
	return slices.Compact(ids)
}
