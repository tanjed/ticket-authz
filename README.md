# Authz

Authorization for the Bus 2.0 platform. It owns the **permission catalogue** (seeded by each service), **company roles** and **who holds which role**, and publishes all of it as **OPA bundles** that the APISIX gateway (`../APISIX`) decides every request from. Authz is never on the request path: it is called at login (by the IdP) and when roles change.

```
login:    IdP ──(provider client)──► Authz GetClaims ──► JWT { sub, user_type, company_id, roles }
request:  client ─► APISIX ─► OPA sidecar (verifies the JWT, decides from bundles) ─► service
bundles:  OPA ◄── long poll ── Authz   (discovery, catalogue + policy, consumer, one per company)
seeding:  service deploy Job ── ApplyManifest ──► Authz (permissions + APISIX route map)
```

- **Permissions** are `resource:action` (`order:create`), no API version. Each service declares its own and maps each of its APISIX routes to exactly one (or marks it public).
- **Consumers** (tokens from consumer clients) get the consumer permission set: the permissions services flag `consumer: true`.
- **Providers** belong to exactly one company. Each company starts with a protected **Admin** role (every permission, can't be edited, always has a holder). Admins create roles and invite staff. Nobody can hand out permissions they don't hold (escalation rule).
- Services still enforce **tenant isolation**: every query scoped by `X-Bus-Company-Id`.

## APIs: gRPC and REST side by side

Defined in `proto/bus/authz/v1`. REST is grpc-gateway over the same implementations (in-process), from the `google.api.http` annotations. OpenAPI: `api/openapi/authz.swagger.json`.

| Listener | REST | gRPC | Reachable from | Serves |
|---|---|---|---|---|
| public | `:8080` | `:9090` | APISIX only | `AdminService` (roles, members, invitations) |
| internal | `:8081` | `:9091` | in-cluster only | `InternalService` (manifests, claims, companies, invitations), `/bundles/*`, `/healthz` |

The public listeners trust the caller the gateway passes (`X-Bus-*` headers, `x-bus-*` gRPC metadata); nothing else may reach them. REST errors are `{"error": <reason>, "message"}`; gRPC errors carry the same reason in `ErrorInfo`.

## Seeding a service

Every deploy, the service's Job sends its manifest (idempotent; entries it drops are deprecated, not deleted):

```sh
curl -X PUT http://authz:8081/internal/v1/manifests/order -H 'content-type: application/json' -d '{
  "permissions": [{"key": "order:create", "description": "Create an order", "consumer": true}],
  "routes": [{"name": "order.create", "permission": "order:create"}, {"name": "order.health", "public": true}]
}'
```

## Quick start (local)

Needs Go, Docker and `make`. Runs on the `shohoz` network with `../IdP` and `../APISIX`.

```sh
make tools generate   # pinned buf + plugins into ./bin, regenerate api/ (only after editing proto/)
make test             # Go tests; the rbac and server tests start a Postgres container
make test-policy      # opa test for the gateway policy
docker compose up -d --build
```

Local ports (loopback): public REST 8090, gRPC 9090; internal REST 8091, gRPC 9091; Postgres 5433. `make seed SERVICE=... FILE=...` seeds a manifest.

## Configuration

| Variable | Meaning |
|---|---|
| `AUTHZ_DATABASE_URL` | Postgres (required) |
| `AUTHZ_PUBLIC_ADDR`, `AUTHZ_PUBLIC_GRPC_ADDR` | Public listeners (`:8080`, `:9090`) |
| `AUTHZ_INTERNAL_ADDR`, `AUTHZ_INTERNAL_GRPC_ADDR` | Internal listeners (`:8081`, `:9091`) |
| `AUTHZ_IDP_INTERNAL_URL` | The IdP UI's cluster-internal URL (invitations; required for `serve`) |
| `AUTHZ_KAFKA_BROKERS`, `AUTHZ_KAFKA_TOPIC` | Events (`authz.events`); no brokers: events are only logged |
| `AUTHZ_BUNDLE_SERVICE`, `AUTHZ_LONG_POLL_SECONDS` | What discovery tells OPA (service name `authz`, 30 s) |
| `AUTHZ_INVITE_TTL` | Invitation lifetime (`168h`) |

## Layout

| Path | Contents |
|---|---|
| `cmd/authz` | Entry point: migrations, own manifest, then serve |
| `proto/`, `api/` | API definitions; generated Go, gateway and OpenAPI (committed) |
| `internal/ioc` | Assembles the app from each package's `fx.Module` (`module.go`) |
| `internal/rbac` | the domain and its SQL |
| `internal/grpcapi` | proto service implementations |
| `internal/server` | gateways, chi routers, gRPC servers, the four listeners |
| `internal/bundle` | OPA bundles: tarballs, long polling |
| `policy/` | the gateway's rego policy (shipped in the catalogue bundle) and its tests |
| `manifest/` | Authz's own manifest (its admin API routes), seeded at startup |
| `migrations/` | goose SQL |
| `chart/`, `helmvars/` | Helm chart (Deployment, Service, NetworkPolicy, ApisixRoute, Postgres) |

## Deploying

```sh
make lint template
helm upgrade --install authz chart -f helmvars/dev.yaml
```

Pre-created Secret `authz-postgres` (keys `password`, `url`); the chart creates no secrets. Authz applies its migrations on every start (advisory lock: replicas starting together are safe).

Design: `docs/superpowers/specs/2026-09-29-authz-service-design.md`.
