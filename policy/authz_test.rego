package bus.authz_test

import rego.v1

import data.bus.authz

# Test-only RSA key (generated for these tests; not used anywhere else).
private_key := {"alg":"RS256","d":"ENZHxM0va03CIXmpuMioh5P6nbQ9qINoCwctoRQqUpdCYjPMqlR5zHl0DsklC4odmovWQl3SiGd05Gzf_0Jxcae8t82Vu20Cio1OSNLJRVYHbosWSAissILtwffSluAk_Va7d7FVVQqRM7o5NqwcL71u_YkYQeKGNE6JcAc1ecwOCqPujzqgjlZFgToO6LGScHBsI_HBMMb45IK6mDn2HKgZch1YOTVA8Y-dubmaRtMEqvbsuee-ucAisWjpth89JhQPbYEbIoI6hy8yMb9QenxHKNVaXHxtAspYMBItbMjBR0bhLPcsYTrWl_UHrIi5Cf9D3rz78DDrXVkiqIcq3Q","dp":"AiuCFUZxud3QT_d-vbGHUd9YsGhti65cE-8DmdWqRNKIYb-Ygl7wZ5KZejPjPPGWNSq3tsKT_F2M9Z5zdUCUgUT9u0DFy2zkCNbu8-SWwcDrcmYg0p53uz4lvJ1T9L_tvUwJv17zmE9vik4qOg5OmugonUHqjjfYojUD8jTLXTE","dq":"kUFkXAJuzokBNpQC86097hmJo_edC60M1efTbwy41jU71hzqdRPaCJI-81hUKu7H58-HiR4QnNuSbZCV_uJBobIFRAx3qGnPQiWoRfMLvp-zWyqTHS4S7dU8y6RSjm_AxRum7sCbkRnB6-8jlkowuSrDKwTDMgZV3Sb5c0wLP_U","e":"AQAB","kid":"test","kty":"RSA","n":"uHoWbhN7mhqjrAUv467-4D5ooQuMu5bTJOxctnwML-qkc7w-fdWBqARNecrLR6xVthAVfl3PbumFojfey0UABo5SSDbZEzoZBLkC7-6gts5Hin9Gjwf4WNVnzbyHyYGGNz26jlb3xvzoUtVkNWI8-0wbFxfv3TIDln2EduwZS1VibcCXbzpoKw3zCbrWoE_fZTyVObrf7bi9_qAcDoz7973LOoz3bUB3YBc1WMF2idUB7XSNBPv6slHXhcBVvR5-50yF167Qzz5Z4JZKuIMqv_3y7m6EIpH_EgX2KthcgpZddClXsMRFEF2dCRnemfcUfvH6NMx2fO1D3uKcAqiB8w","p":"0l-HHPsTz1oyqZV5oi9XoZPnq5g4Fq-f6_a8J90y7iBERawGzc2MT-gpNAUXCWavPnT4_FLWs1PQuhilAAOx7mOZFifIBxN83kiho2yNw0kqJ_spLrCbKBibjglOCo9VSuXi_r_8sN0aaSqdn0Fi69brVEWcExZJfNZmtg46UG0","q":"4Hy7UiFpvFyUgTiGyiPeaCUjJ-MgLBslGKuybm11xeneerK4Iw1P3tjdtUJReCPBZq8W-vNks2ShaK-GlUHjv0IlWDWU4ws9GuTP-vL1X4Me9l1eO_cppFAWzPJhyjzGR9E5-wwHA1o4qQoBmjRrFyRttoTGxm3xaWvMVoeUX98","qi":"HaMl5CH6Hj2dRkolDmHOPbFLGxdwOWCkadea8J2-47vL4O4kYXFuWF91FNuFRfBdaVjIyKbkeBNq2yMd2r5l5Nt2L2YYA2EX-TQnbGapcZ3E4j_152VgxbaSRIGTdTSs9Cs12m1fd8NPZWfGGqinzNaf7F4xpciqa2ZTQgwnGNA"}

jwks := `{"keys":[{"alg":"RS256","e":"AQAB","kid":"test","kty":"RSA","n":"uHoWbhN7mhqjrAUv467-4D5ooQuMu5bTJOxctnwML-qkc7w-fdWBqARNecrLR6xVthAVfl3PbumFojfey0UABo5SSDbZEzoZBLkC7-6gts5Hin9Gjwf4WNVnzbyHyYGGNz26jlb3xvzoUtVkNWI8-0wbFxfv3TIDln2EduwZS1VibcCXbzpoKw3zCbrWoE_fZTyVObrf7bi9_qAcDoz7973LOoz3bUB3YBc1WMF2idUB7XSNBPv6slHXhcBVvR5-50yF167Qzz5Z4JZKuIMqv_3y7m6EIpH_EgX2KthcgpZddClXsMRFEF2dCRnemfcUfvH6NMx2fO1D3uKcAqiB8w","use":"sig"}]}`

mock_runtime := {"env": {"OPA_JWKS_URL": "http://hydra/jwks", "OPA_ISSUER": "http://hydra/", "OPA_AUDIENCE": "bus-api"}}

mock_send(req) := {"status_code": 200, "raw_body": jwks} if req.url == "http://hydra/jwks"

base_claims := {"iss": "http://hydra/", "aud": ["bus-api"], "exp": 4102444800, "sub": "user-1", "client_id": "app"}

token(claims) := io.jwt.encode_sign({"alg": "RS256", "typ": "JWT", "kid": "test"}, object.union(base_claims, claims), private_key)

consumer_token := token({"user_type": "consumer"})

clerk_token := token({"user_type": "provider", "company_id": "c1", "roles": [{"id": "r-clerk", "name": "Clerk", "version": 1}]})

admin_token := token({"user_type": "provider", "company_id": "c1", "roles": [{"id": "r-admin", "name": "Admin", "version": 1}]})

catalogue := {"routes": {
	"order.create": {"permission": "order:create"},
	"order.cancel": {"permission": "order:cancel"},
	"health": {"public": true},
}}

consumer := {"permissions": {"order:create": true}}

companies := {
	"c1": {"status": "active", "roles": {
		"r-admin": {"grants_all": true, "permissions": {}},
		"r-clerk": {"grants_all": false, "permissions": {"order:create": true}},
	}},
	"c2": {"status": "suspended", "roles": {"r-admin": {"grants_all": true, "permissions": {}}}},
}

decide(route_name, headers) := d if {
	d := authz.decision with input as {"route": {"name": route_name}, "request": {"headers": headers}}
		with data.catalogue as catalogue
		with data.consumer as consumer
		with data.companies as companies
		with opa.runtime as mock_runtime
		with http.send as mock_send
}

bearer(t) := {"authorization": concat(" ", ["Bearer", t])}

test_unknown_route_denied if {
	d := decide("nope", bearer(admin_token))
	d.allow == false
	d.status_code == 403
}

test_gateway_catch_all_is_404 if {
	decide("gateway.not_found", bearer(admin_token)).status_code == 404
}

test_public_route_needs_no_token if {
	d := decide("health", {})
	d.allow == true
	not d.headers
}

test_missing_token_is_401 if {
	decide("order.create", {}).status_code == 401
}

test_non_bearer_scheme_is_401 if {
	decide("order.create", {"authorization": concat(" ", ["Basic", consumer_token])}).status_code == 401
}

test_tampered_token_is_401 if {
	[h, _, s] := split(consumer_token, ".")
	forged := base64url.encode_no_pad(json.marshal(object.union(base_claims, {"user_type": "provider", "company_id": "c1", "roles": [{"id": "r-admin"}]})))
	decide("order.cancel", bearer(concat(".", [h, forged, s]))).status_code == 401
}

test_expired_token_is_401 if {
	decide("order.create", bearer(token({"user_type": "consumer", "exp": 1000}))).status_code == 401
}

test_wrong_audience_is_401 if {
	decide("order.create", bearer(token({"user_type": "consumer", "aud": ["other"]}))).status_code == 401
}

test_wrong_issuer_is_401 if {
	decide("order.create", bearer(token({"user_type": "consumer", "iss": "http://evil/"}))).status_code == 401
}

test_consumer_allowed_consumer_permission if {
	d := decide("order.create", bearer(consumer_token))
	d.allow == true
	d.headers == {"X-Bus-Subject": "user-1", "X-Bus-User-Type": "consumer", "X-Bus-Client-Id": "app"}
}

test_consumer_denied_other_permission if {
	d := decide("order.cancel", bearer(consumer_token))
	d.allow == false
	d.status_code == 403
}

test_consumer_ignores_provider_claims if {
	t := token({"user_type": "consumer", "company_id": "c1", "roles": [{"id": "r-admin"}]})
	decide("order.cancel", bearer(t)).status_code == 403
}

test_provider_role_permission_allowed if {
	d := decide("order.create", bearer(clerk_token))
	d.allow == true
	d.headers["X-Bus-Company-Id"] == "c1"
	d.headers["X-Bus-User-Type"] == "provider"
}

test_provider_missing_permission_denied if {
	decide("order.cancel", bearer(clerk_token)).status_code == 403
}

test_grants_all_allows_everything if {
	decide("order.cancel", bearer(admin_token)).allow == true
}

test_suspended_company_denied if {
	t := token({"user_type": "provider", "company_id": "c2", "roles": [{"id": "r-admin"}]})
	decide("order.create", bearer(t)).status_code == 403
}

test_unknown_company_denied if {
	t := token({"user_type": "provider", "company_id": "c9", "roles": [{"id": "r-admin"}]})
	decide("order.create", bearer(t)).status_code == 403
}

test_role_of_another_company_denied if {
	t := token({"user_type": "provider", "company_id": "c1", "roles": [{"id": "r-other"}]})
	decide("order.create", bearer(t)).status_code == 403
}

test_missing_user_type_denied if {
	decide("order.create", bearer(token({}))).status_code == 403
}

test_jwks_unreachable_is_401 if {
	d := authz.decision with input as {"route": {"name": "order.create"}, "request": {"headers": bearer(consumer_token)}}
		with data.catalogue as catalogue
		with data.consumer as consumer
		with opa.runtime as mock_runtime
		with http.send as {"status_code": 0, "raw_body": ""}
	d.status_code == 401
}
