# Gateway decision for every APISIX request (global `opa` plugin, policy bus/authz/decision).
# Shipped in the catalogue bundle; data comes from the other bundles Authz serves:
#   data.catalogue.routes[<route name>] = {"permission": "order:create"} | {"public": true}
#   data.consumer.permissions[<permission>] = true
#   data.companies[<company id>] = {"status", "roles": {<role id>: {"grants_all", "permissions"}}}
# Environment (OPA container): OPA_JWKS_URL, OPA_ISSUER, OPA_AUDIENCE.
package bus.authz

import rego.v1

env := opa.runtime().env

route := data.catalogue.routes[input.route.name]

bearer := token if {
	auth := input.request.headers.authorization
	startswith(auth, "Bearer ")
	token := substring(auth, 7, -1)
}

# Hydra's JWKS, cached for a minute. A key added at rotation is honoured within that minute.
jwks := http.send({
	"method": "GET",
	"url": env.OPA_JWKS_URL,
	"force_cache": true,
	"force_cache_duration_seconds": 60,
	"raise_error": false,
}).raw_body

# The verified token payload; undefined when the token is missing, forged, expired or not ours.
claims := payload if {
	[valid, _, payload] := io.jwt.decode_verify(bearer, {
		"cert": jwks,
		"iss": env.OPA_ISSUER,
		"aud": env.OPA_AUDIENCE,
	})
	valid
}

permitted if {
	claims.user_type == "consumer"
	data.consumer.permissions[route.permission]
}

permitted if {
	claims.user_type == "provider"
	company := data.companies[claims.company_id]
	company.status == "active"
	some ref in claims.roles
	role_allows(company.roles[ref.id])
}

role_allows(role) if role.grants_all

role_allows(role) if role.permissions[route.permission]

# Set on the upstream request; APISIX removes any of these the decision leaves out, so a
# client-supplied value never reaches a service.
identity := object.union(
	{
		"X-Bus-Subject": claims.sub,
		"X-Bus-User-Type": claims.user_type,
		"X-Bus-Client-Id": object.get(claims, "client_id", ""),
	},
	company_header,
)

company_header := {"X-Bus-Company-Id": claims.company_id} if {
	claims.user_type == "provider"
} else := {}

# The gateway's lowest-priority catch-all route. APISIX's opa plugin fails (500) when no route
# matched, so the gateway always has one; it answers 404.
not_found_route := "gateway.not_found"

decision := {"allow": false, "status_code": 404, "reason": "not found"} if {
	input.route.name == not_found_route
} else := {"allow": false, "status_code": 403, "reason": "unknown route"} if {
	not route
} else := {"allow": true} if {
	route.public
} else := {"allow": false, "status_code": 401, "reason": "unauthenticated"} if {
	not claims
} else := {"allow": true, "headers": identity} if {
	permitted
} else := {"allow": false, "status_code": 403, "reason": "forbidden"}
