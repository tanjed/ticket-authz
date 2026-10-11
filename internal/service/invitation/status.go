package invitation

import (
	"time"
)

// Invitation statuses, derived from the invitation's times (never stored).
const (
	Pending  = "pending"
	Accepted = "accepted"
	Expired  = "expired"
)

// status is an invitation's status at now.
func status(i Invitation, now time.Time) string {
	switch {
	case i.AcceptedAt != nil:
		return Accepted
	case !now.Before(i.ExpiresAt):
		return Expired
	default:
		return Pending
	}
}
