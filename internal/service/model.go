package service

import "time"

// AdminRoleName is the protected role every company starts with.
const AdminRoleName = "Admin"

// Company statuses.
const (
	StatusActive    = "active"
	StatusSuspended = "suspended"
)

// Caller is the gateway-verified user behind an admin API request (X-Bus-Subject, X-Bus-Company-Id).
type Caller struct {
	Sub       string
	CompanyID string
}

type Role struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Protected   bool      `json:"protected"`
	GrantsAll   bool      `json:"grants_all"`
	Version     int       `json:"version"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RoleInput is the body of role create and update.
type RoleInput struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type Member struct {
	Sub       string    `json:"sub"`
	RoleIDs   []string  `json:"role_ids"`
	CreatedAt time.Time `json:"created_at"`
}

// Membership is a subject's company, its status and the subject's authorization version.
type Membership struct {
	CompanyID     string
	CompanyStatus string
	AuthzVersion  int64
}

// RoleRef is a role as it appears in the token.
type RoleRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Claims is what the IdP puts in a provider's access token. AuthzVersion is the member's
// authorization version: the gateway refuses the token once the view holds another.
type Claims struct {
	CompanyID    string    `json:"company_id"`
	Roles        []RoleRef `json:"roles"`
	AuthzVersion int64     `json:"authz_version"`
}

type Invitation struct {
	ID          string     `json:"id"`
	CompanyID   string     `json:"company_id"`
	CompanyName string     `json:"company_name"`
	Phone       string     `json:"phone"`
	RoleIDs     []string   `json:"role_ids"`
	InvitedBy   string     `json:"invited_by"`
	Sub         *string    `json:"sub"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	CreatedAt   time.Time  `json:"created_at"`
	Status      string     `json:"status"`
}

// InvitationInput is the body of POST /v1/invitations.
type InvitationInput struct {
	Phone   string   `json:"phone"`
	RoleIDs []string `json:"role_ids"`
}

// PendingInvitation is what accepting an invitation reads under lock.
type PendingInvitation struct {
	CompanyID  string
	RoleIDs    []string
	ExpiresAt  time.Time
	AcceptedAt *time.Time
}

// PermissionInfo is one catalogue entry, as the admin API lists it.
type PermissionInfo struct {
	Key         string `json:"key"`
	Service     string `json:"service"`
	Description string `json:"description"`
}

// ManifestResult summarises an applied manifest.
type ManifestResult struct {
	Service     string `json:"service"`
	Permissions int    `json:"permissions"`
	Routes      int    `json:"routes"`
	// Changed is false when the manifest matched what was stored (the gateway view untouched).
	Changed bool `json:"changed"`
}
