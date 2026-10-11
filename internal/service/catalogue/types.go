package catalogue

import catalogrepo "github.com/tanjed/bus2/authz/internal/repository/catalogue"

// Permission is one catalogue entry, as the admin API lists it.
type Permission = catalogrepo.PermissionInfo

// Result summarises an applied manifest.
type Result struct {
	Service     string `json:"service"`
	Permissions int    `json:"permissions"`
	Routes      int    `json:"routes"`
	// Changed is false when the manifest matched what was stored (the gateway view untouched).
	Changed bool `json:"changed"`
}
