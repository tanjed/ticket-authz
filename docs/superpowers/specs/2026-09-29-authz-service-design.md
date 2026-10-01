# Authz service design

Date: 2026-09-29. Status: approved in brainstorming; built in this round.

Companion specs: `../APISIX/docs/superpowers/specs/2026-09-29-apisix-gateway-design.md` (gateway, OPA sidecar) and `../IdP/docs/superpowers/specs/2026-09-29-idp-authz-integration-design.md` (claims at login, company onboarding, staff invites).

## 1. Goal

Centralized authorization for Bus 2.0 without a central service on the request path.

- Authz owns the permission catalogue, company roles, and who holds which role.
- The IdP asks Authz for a user's company and roles once, at login, and puts them in the JWT.
- APISIX decides every request locally: an OPA sidecar in the gateway pod verifies the JWT against Hydra's JWKS and checks the route's permission against bundles that Authz publishes. Authz being down never blocks a request, only new provider logins.
- Services do not re-check permissions. They enforce **tenant isolation** (every query scoped by `X-Bus-Company-Id`) and their own business rules.
- Service-to-service calls are unauthenticated and stay inside the private network.

`../Auth` is unrelated to this work and stays as it is.

## 2. System overview

```
login:    browser ─► IdP (Hydra + Kratos + UI) ──(provider client)──► Authz  GET claims
                                                  └──► JWT { sub, user_type, company_id, roles[] }

request:  client ─► APISIX ─(global opa plugin)─► OPA sidecar (localhost)
                                                   ├─ verify JWT (Hydra JWKS, cached)
                                                   └─ decide from bundles
                     └─ allow ─► service (reads X-Bus-* headers, filters by company)

bundles:  OPA ◄─(long poll)── Authz /bundles/*   (discovery, catalogue, consumer, companies/<id>)
seeding:  service deploy Job ──PUT manifest──► Authz (permissions + route map)
```

## 3. Vocabulary

- **Permission**: `resource:action`, e.g. `order:create`, `role:manage`. No API version in the key: `/v1/orders` and `/v2/orders` may require the same permission. Pattern `^[a-z][a-z0-9_-]*:[a-z][a-z0-9_.-]*$`.
- **Route**: an APISIX route, identified by its `name` (which the `opa` plugin sends as `input.route.name`). Each route maps to exactly one permission, or is marked public.
- **User type**: `provider` (belongs to exactly one company, has roles) or `consumer` (no company, gets the consumer permission set). Decided by the OAuth client the user signs in through, never by which claims happen to be present.
- **Role**: company-owned, a named set of permissions. The **protected admin role** (`protected`, `grants_all`) is created with the company, holds every permission (including ones added later), cannot be edited or deleted, and each company always keeps at least one holder.

## 4. Seeding (catalogue)

Each service owns its permissions and its APISIX routes. On every deploy a Job sends its manifest:

`PUT /internal/v1/manifests/{service}` with JSON body:

```json
{
  "permissions": [
    { "key": "order:create", "description": "Create an order", "consumer": true },
    { "key": "order:cancel", "description": "Cancel any order" }
  ],
  "routes": [
    { "name": "order.create", "permission": "order:create" },
    { "name": "order.health", "public": true }
  ]
}
```

Rules:
- The manifest replaces that service's previous one. Permissions and routes missing from it get `deprecated_at` (never deleted: role links survive a rollback). A re-seed un-deprecates.
- A permission key or route name already owned by another service is a conflict (409). Ownership moves only by removing it from the old service first.
- Every route references a permission from the same manifest, or is `public`. Nothing else.
- `consumer: true` puts the permission in the consumer set.
- Deprecated permissions and routes are left out of the bundles, so they are denied.
- The call is idempotent; re-running a Job changes nothing. A failed seed fails the Job and therefore the deploy.
- Authz seeds its own manifest (`manifest/authz.json`, embedded) at startup.

## 5. Data model (Postgres, goose migrations)

- `permissions(key pk, service, description, consumer bool, deprecated_at)`
- `routes(name pk, service, permission_key null, public bool, deprecated_at)`; `permission_key` set xor `public`.
- `companies(id uuid pk, name, status active|suspended, created_at)`
- `roles(id uuid pk, company_id, name, protected bool, grants_all bool, version int, created_at, updated_at)`; unique `(company_id, lower(name))`.
- `role_permissions(role_id, permission_key)`
- `members(sub pk, company_id, created_at)`: `sub` is the primary key, which is what enforces "one company per user".
- `member_roles(sub, role_id)`
- `invitations(id uuid pk, company_id, phone, role_ids uuid[], invited_by, sub null, expires_at, accepted_at null, created_at)`
- `bundle_revisions(name pk, revision bigint)`: one row per bundle, bumped in the same transaction as any write that changes it.

Every role, member and invitation query is scoped by `company_id`.

## 6. APIs

Defined in proto (`proto/bus/authz/v1`): `AdminService` and `InternalService`, implemented as Connect handlers. Vanguard serves each as **Connect, gRPC, gRPC-Web and REST on one port** (HTTP/1.1 and h2c); REST is driven by the `google.api.http` annotations. REST JSON uses the proto field names (snake_case), emits empty fields, and refuses unknown fields. Errors: the Connect/gRPC error carries an `ErrorInfo` whose reason is the domain code (e.g. `last_admin`); REST answers `{"error": <reason>, "message"}` with the standard gRPC-to-HTTP status mapping. (Changed 2026-10-01 from grpc-go + grpc-gateway on four ports; see `2026-10-01-connect-vanguard-signed-bundles-design.md`.)

Two trust zones, two listeners:

| Zone | Port | Reachable from | Serves |
|---|---|---|---|
| public | `:8080` | APISIX only (NetworkPolicy) | `AdminService`; trusts `X-Bus-*` headers |
| internal | `:8081` | in-cluster, never routed by the gateway | `InternalService`, OPA bundles (`/bundles/*`, plain HTTP), `/healthz` |

Domain errors map to gRPC codes: invalid input `INVALID_ARGUMENT`, not allowed `PERMISSION_DENIED`, not found `NOT_FOUND`, conflicts (name taken, already used, already a member, owned elsewhere) `ALREADY_EXISTS` (409), state rules (protected role, role in use, last admin, expired) `FAILED_PRECONDITION` (400), IdP down `UNAVAILABLE` (503). The status codes in the tables below are the REST view.

### 6.1 Internal (`:8081`)

| Method and path | Caller | Result |
|---|---|---|
| `PUT /internal/v1/manifests/{service}` | service seed Job | 200 summary; 400 invalid; 409 ownership conflict |
| `GET /internal/v1/subjects/{sub}/claims` | IdP (login and consent) | 200 `{company_id, roles:[{id,name,version}]}`; 404 not a member; 403 company suspended |
| `POST /internal/v1/companies` `{name, admin_sub}` | IdP (company onboarding) | 200 `{company_id, created}`; `created: false` if `admin_sub` already belongs to a company (idempotent retry) |
| `PUT /internal/v1/companies/{company_id}/status` `{status}` | platform operations | 200; `COMPANY_STATUS_ACTIVE` or `COMPANY_STATUS_SUSPENDED` |
| `GET /internal/v1/invitations/{id}` | IdP (invite page) | 200 `{invitation: {id, company_name, phone, expire_time, status, ...}}`; status `INVITATION_STATUS_PENDING`, `_ACCEPTED` or `_EXPIRED` |
| `POST /internal/v1/invitations/{id}/accept` `{sub}` | IdP (invite submit) | 200; 409 already accepted or member of a company; 400 `expired`; 404 unknown |
| `GET /bundles/{name}` | OPA | bundle tarball, long polling (7) |
| `GET /healthz` | kubelet | 200 |

### 6.2 Public, company admin API (`:8080`, routed by APISIX under `/authz`)

The caller is `X-Bus-Subject` of `X-Bus-Company-Id`; `X-Bus-User-Type` must be `provider` (else 403). The gateway already checked the route's permission; Authz additionally enforces tenant scoping, the escalation rule, and the protected-role rules.

| Route name | Method and path | Permission |
|---|---|---|
| `authz.permissions.list` | `GET /v1/permissions` | `role:read` |
| `authz.roles.list` | `GET /v1/roles` | `role:read` |
| `authz.roles.get` | `GET /v1/roles/{id}` | `role:read` |
| `authz.roles.create` | `POST /v1/roles` `{name, permissions[]}` | `role:manage` |
| `authz.roles.update` | `PUT /v1/roles/{id}` `{name, permissions[]}` | `role:manage` |
| `authz.roles.delete` | `DELETE /v1/roles/{id}` | `role:manage` |
| `authz.members.list` | `GET /v1/members` | `member:read` |
| `authz.members.roles` | `PUT /v1/members/{sub}/roles` `{role_ids[]}` | `member:manage` |
| `authz.members.remove` | `DELETE /v1/members/{sub}` | `member:manage` |
| `authz.invitations.list` | `GET /v1/invitations` | `member:read` |
| `authz.invitations.create` | `POST /v1/invitations` `{phone, role_ids[]}` | `member:manage` |

Rules:
- **Escalation**: the caller may create or edit a role only if its permissions are a subset of the caller's own effective permissions (read fresh from the database, not from the token), and may assign or invite with a role only under the same condition. A `grants_all` role can be assigned only by a caller who holds `grants_all`.
- **Protected admin role**: cannot be updated or deleted. Removing it from its last holder, or removing its last holder from the company, is refused (409).
- A role still assigned to anyone cannot be deleted (409).
- A role edit bumps `roles.version`. Every write bumps the company bundle revision.
- Errors: 400 invalid body, 403 escalation or wrong user type, 404 outside the caller's company (never "exists elsewhere"), 409 conflicts.

### 6.3 Invitations

1. `POST /v1/invitations {phone, role_ids}`: Authz normalises the phone (E.164), then asks the IdP `GET /api/internal/identities?phone=`. If an identity exists and is a member of any company (including this one), 409 `cannot_invite` (one generic answer).
2. Authz stores the invitation (7-day expiry) and calls the IdP `POST /api/internal/invitations {invitation_id, phone, company_name, expires_at}`, which sends the SMS link. If that call fails the invitation is deleted and the admin gets 502.
3. The IdP invite page reads `GET /internal/v1/invitations/{id}`, creates the identity if needed (or reuses the existing one), then `POST .../accept {sub}`. Authz, in one transaction: checks pending and unexpired, checks `sub` is not a member anywhere, inserts the member with the invited roles, sets `accepted_at`, bumps the company bundle.

## 7. Bundles

OPA's boot config names one service (`authz`, the internal listener) and enables **discovery**. Everything else comes from Authz.

| Bundle | Path | Data | Roots |
|---|---|---|---|
| discovery | `/bundles/discovery.tar.gz` | `bus.config.bundles`: `catalogue`, `consumer`, and one `companies/<id>` per company | n/a (discovery) |
| catalogue | `/bundles/catalogue.tar.gz` | `catalogue.routes[name] = {permission} or {public:true}`; the rego policy `bus.authz` | `catalogue`, `bus/authz` |
| consumer | `/bundles/consumer.tar.gz` | `consumer.permissions[key] = true` | `consumer` |
| company | `/bundles/companies/<id>.tar.gz` | `companies[<id>] = {status, roles: {<role_id>: {grants_all, permissions: {key: true}}}}` | `companies/<id>` |

- **Revision and ETag**: `bundle_revisions.revision` is the `.manifest` revision and the `ETag`. A write bumps the affected rows in its own transaction and issues `NOTIFY authz_bundles, '<name>'`, delivered on commit to every Authz replica.
- **Long polling**: OPA sends `If-None-Match` and `Prefer: wait=<seconds>`. If the ETag is current, Authz holds the request until a notification for that bundle or the wait expires (then 304). Responses carry `Content-Type: application/vnd.openpolicyagent.bundles`, which OPA requires to keep long polling.
- **Build**: on request, from one read-only repeatable-read transaction; cached in memory per `(name, revision)`. Written with OPA's own bundle package and **signed** (RS256, `.signatures.json`); discovery tells OPA to verify every bundle (`signing.keyid`), and OPA's boot config holds the public key and verifies discovery itself.
- What bumps what: a manifest bumps `catalogue` and `consumer`. Company creation bumps `discovery` and creates `companies/<id>`. Role, member or status changes bump `companies/<id>`.
- Scale: every OPA loads every company (any gateway replica serves any company). Per-company bundles make a role edit rebuild and re-download one small bundle. Each OPA holds one long poll per bundle.

## 8. Policy (rego, served in the catalogue bundle)

Package `bus.authz`, decision `data.bus.authz.decision`, returned to APISIX as `{allow, status_code?, reason?, headers?}`:

1. Route unknown or deprecated: deny 403.
2. Route public: allow, no identity headers.
3. No bearer token, or it fails `io.jwt.decode_verify` (JWKS fetched with `http.send`, cached 60 s; `iss`, `aud`, `exp`): deny 401.
4. `user_type == "consumer"`: allow if the route's permission is in `data.consumer.permissions`.
5. `user_type == "provider"`: allow if the company exists and is active, and one of the token's `roles` is in that company's bundle with `grants_all` or the route's permission.
6. Anything else: deny 403.

On allow the decision sets `X-Bus-Subject`, `X-Bus-User-Type`, `X-Bus-Company-Id` and `X-Bus-Client-Id`; APISIX's `send_headers_upstream` removes any of them the decision leaves out, so client-supplied values never reach a service. The JWKS URL, issuer and audience come from OPA's environment (`opa.runtime().env`), so the policy has no environment-specific values.

## 9. Events

Authz publishes to its own topic, `authz.events`, with the IdP's envelope `{id, event, occurred_at, source: "authz", data}`, keyed by `company_id`: `COMPANY_REGISTERED`, `ROLE_CREATED`, `ROLE_UPDATED`, `ROLE_DELETED`, `MEMBER_ADDED`, `MEMBER_ROLES_CHANGED`, `MEMBER_REMOVED`, `MEMBER_INVITED`. Published after commit; a Kafka failure is logged and the request still succeeds (no outbox yet).

## 10. Failure modes

- Authz down: provider logins and token refreshes fail at the IdP; requests keep working on the last bundles; consumers are unaffected. OPA with no bundle loaded answers nothing, and APISIX's `opa` plugin denies.
- Postgres down: Authz fails closed (5xx) on every API; bundle long polls return what is cached.
- Kafka down: events are lost (logged).

## 11. Staleness (known, parked)

- Role **definition** changes: within one long poll (seconds).
- Role **assignment** changes and member removal: at the next token issuance. Hydra copies consent claims into refreshed tokens, so the bound is the refresh chain unless the IdP re-computes claims on refresh (Hydra `token_hook`). Decision parked.

## 12. Build

Go (module `github.com/tanjed/bus2/authz`). Dependency wiring with **uber fx** (each package owns its `fx.Module`; `internal/ioc` lists them and returns the app); on boot the service applies its migrations (goose, Postgres advisory lock), seeds its own manifest, then serves; routing with **chi**; APIs from **proto** (buf, protoc-gen-go, protoc-gen-connect-go, openapiv2; served by connect-go and Vanguard; pinned tools in `./bin` via `make tools`; generated code in `api/gen` and `api/openapi`, committed, `make check-generated` catches drift); pgx, goose, franz-go.

Packages: `config`, `db` (pool, migrations), `catalogue` (manifest validation), `rbac` (domain and SQL: catalogue, companies, roles, members, invitations, bundle snapshots; transport-neutral error kinds), `bundle` (signed tarballs via OPA's bundle package, long-poll hub, Postgres listener), `rpcapi` (the proto service implementations as Connect handlers, error and caller mapping), `server` (Vanguard transcoders, chi routers, the two listeners), `idp` (IdP internal client), `events`, `logging`, `ioc` (assembles the modules), `testdb` (test Postgres). Policy and its tests live in `policy/`. Chart: Deployment (two ports), Service, NetworkPolicy, the `ApisixRoute` for the admin API, bundled Postgres. Compose: Authz and its Postgres on the `shohoz` network.

## 13. Testing

- Go unit tests: manifest validation, escalation, bundle tarball layout, long-poll hub.
- Go integration tests against Postgres (testcontainers): seeding, claims, company creation, role and member rules, invitations, bundle revisions.
- `opa test policy/` (via the OPA container): every decision rule, including token verification with a test key.
- End to end with docker-compose: IdP + Authz + APISIX + OPA + an echo service; provider signup, company creation, role edits reflected in decisions, consumer access, staff invite.

## 13a. Not in this round

- A generator that produces both the `ApisixRoute` and the manifest from one route file (drift is caught by deny-by-default and the CI check below, not prevented).
- CI comparing APISIX route names with seeded route names.
- Outbox for events; Hydra `token_hook` for fresh claims on refresh; per-subject revocation list in bundles.
- Third-party client consent screen (third parties act with the user's full permissions, as decided).
