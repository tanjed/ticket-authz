// Package manifest embeds Authz's own manifest: the admin API's permissions and APISIX routes.
// Authz seeds it into its own catalogue at startup, like any service's seed Job would. The route
// names must match the ApisixRoute in chart/templates/apisixroute.yaml.
package manifest

import _ "embed"

//go:embed authz.json
var JSON []byte

// Service is the name Authz's own entries are owned by.
const Service = "authz"
