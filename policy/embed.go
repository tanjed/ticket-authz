// Package policy embeds the gateway's rego policy, shipped to OPA in the catalogue bundle.
// Tests: make test-policy (opa test, in the OPA container).
package policy

import _ "embed"

//go:embed authz.rego
var Rego []byte
