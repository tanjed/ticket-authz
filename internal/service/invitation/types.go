package invitation

import (
	"slices"

	invitationrepo "github.com/tanjed/bus2/authz/internal/repository/invitation"
)

// Invitation is an invitation with its company's name and derived status.
type Invitation = invitationrepo.Invitation

// Input is the body of POST /v1/invitations.
type Input struct {
	Phone   string   `json:"phone"`
	RoleIDs []string `json:"role_ids"`
}

// dedupe sorts ids and drops duplicates, in place.
func dedupe(ids []string) []string {
	slices.Sort(ids)
	return slices.Compact(ids)
}
