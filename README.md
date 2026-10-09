# Authz

Authorization for the Bus 2.0 platform. It owns the **permission catalogue** (seeded by each service), **company roles** and **who holds which role**, and writes all of it to the **gateway view** in Redis: Authz writes the master, the APISIX gateway (`../APISIX`) reads a replica and decides every request from it. Authz is never on the request path: it is called at login (by the IdP) and when roles change.

```
login:    IdP ──(provider client)──► Authz GetClaims ──► JWT { sub, user_type, company_id, roles, authz_version }
request:  client ─► APISIX (verifies the JWT, decides from the Redis replica) ─► service
writes:   Authz ── after each commit ──► Redis master ──► replica (the gateway's)
seeding:  service deploy Job ── ApplyManifest ──► Authz (permissions + APISIX route map)
```

- **Permissions** are `resource:action` (`order:create`), no API version. Each service declares its own and maps each of its APISIX routes to exactly one (or marks it public).
- **Consumers** (tokens from consumer clients) get the consumer permission set: the permissions services flag `consumer: true`.
- **Providers** belong to exactly one company. Each company starts with a protected **Admin** role (every permission, can't be edited, always has a holder). Admins create roles and invite staff. Nobody can hand out permissions they don't hold (escalation rule).
- Services still enforce **tenant isolation**: every query scoped by `X-Bus-Company-Id`.

## APIs: Connect, gRPC, gRPC-Web and REST on one port

Defined in `proto/bus/authz/v1`. The services are [Connect](https://connectrpc.com) handlers; [Vanguard](https://github.com/connectrpc/vanguard-go) serves them as Connect, gRPC and gRPC-Web, and as REST from the `google.api.http` annotations. Each listener speaks HTTP/1.1 and cleartext HTTP/2 (h2c). OpenAPI: `api/openapi/authz.swagger.json`.

| Listener | Port | Reachable from | Serves |
|---|---|---|---|
| public | `:8080` | APISIX only | `AdminService` (roles, members, invitations), `HealthService` |
| internal | `:8081` | in-cluster only | `InternalService` (manifests, claims, companies, invitations), `HealthService` |

`HealthService` is the kubelet's probes: `GET /live` (liveness: the process answers, no dependency checked, so a DB outage never restarts pods) and `GET /ready` (readiness: pings every dependency; 503 / `UNAVAILABLE` naming the failed ones). No gRPC health or server reflection: tools read the schema from `proto/` (`buf curl --schema .`, `grpcurl -import-path proto -proto ...`). The public listener trusts the caller the gateway passes (`X-Bus-*` headers, also gRPC metadata); nothing else may reach it. REST errors are `{"error": <reason>, "message"}`; Connect and gRPC errors carry the same reason in `ErrorInfo`.

```sh
buf curl --schema . --protocol grpc --http2-prior-knowledge -d '{"sub":"u1"}' http://localhost:8091/bus.authz.v1.InternalService/GetClaims
curl localhost:8091/internal/v1/subjects/u1/claims
```

## The gateway view (Redis)

The key contract the gateway reads, and its decision, are in `docs/superpowers/specs/2026-10-06-redis-gateway-view-design.md`. In short: `authz:routes` (route → permission or `public`), `authz:consumer`, `authz:company:<id>` (status), `authz:company:<id>:role:<id>` (permissions, `*` for the admin role), `authz:user:<sub>:version`. A provider token whose `authz_version` differs from the view is refused (`401 token_stale`): the client refreshes it. Role permission edits and suspensions apply at once without a refresh. Each write updates its keys after commit; every boot rebuilds the whole view.

## Seeding a service

Every deploy, the service's Job sends its manifest (idempotent; entries it drops are deprecated, not deleted):

```sh
curl -X PUT http://authz:8081/internal/v1/manifests/order -H 'content-type: application/json' -d '{
  "permissions": [{"key": "order:create", "description": "Create an order", "consumer": true}],
  "routes": [{"name": "order.create", "permission": "order:create"}, {"name": "order.health", "public": true}]
}'
```

## Quick start (local)

Needs Go, Docker and `make`. Runs on the `shohoz` network with `../Infra` (Redis), `../IdP` and `../APISIX`.

```sh
make tools generate   # pinned buf + plugins into ./bin, regenerate api/ (only after editing proto/)
make test             # Go tests; the rbac and server tests start a Postgres container (Redis: miniredis)
(cd ../Infra && docker compose up -d)
docker compose up -d --build
```

Local ports (loopback): public 8090, internal 8091 (every protocol on each); Postgres 5433. `make seed SERVICE=... FILE=...` seeds a manifest.

## Configuration

| Variable | Meaning |
|---|---|
| `AUTHZ_DATABASE_URL` | Postgres (required) |
| `AUTHZ_PUBLIC_ADDR` | Public listener (`:8080`) |
| `AUTHZ_INTERNAL_ADDR` | Internal listener (`:8081`) |
| `AUTHZ_REDIS_URL` | The Redis master the gateway view is written to (required) |
| `AUTHZ_IDP_INTERNAL_URL` | The IdP UI's cluster-internal URL (invitations; required for `serve`) |
| `AUTHZ_KAFKA_BROKERS`, `AUTHZ_KAFKA_TOPIC` | Events (`authz.events`); no brokers: events are only logged |
| `AUTHZ_INVITE_TTL` | Invitation lifetime (`168h`) |

## Layout

| Path | Contents |
|---|---|
| `cmd/authz` | Entry point: migrations, own manifest, gateway view rebuild, then serve |
| `proto/`, `api/` | API definitions; generated Go (messages, Connect handlers and clients) and OpenAPI (committed) |
| `internal/ioc` | Assembles the app from each package's `fx.Module` (`module.go`) |
| `internal/rbac` | the domain and its SQL |
| `internal/admin` | AdminService handler (public listener), over `rbac` |
| `internal/internalapi` | InternalService handler (internal listener), over `rbac` |
| `internal/router` | services per listener, Vanguard transcoders, chi routers, Connect options, error mapping |
| `internal/server` | the two listeners |
| `internal/redisview` | the gateway view in Redis (the key contract) |
| `internal/health` | readiness probes (each dependency's package contributes one), HealthService handler |
| `manifest/` | Authz's own manifest (its admin API routes), seeded at startup |
| `migrations/` | goose SQL |
| `chart/`, `helmvars/` | Helm chart (Deployment, Service, NetworkPolicy, ApisixRoute, Postgres) |

## Deploying

```sh
make lint template
helm upgrade --install authz chart -f helmvars/dev.yaml
```

Pre-created Secrets `authz-postgres` (keys `password`, `url`) and `authz-redis` (key `url`, the platform's Redis master); the chart creates no secrets. Authz applies its migrations on every start (advisory lock: replicas starting together are safe).

Design: `docs/superpowers/specs/2026-09-29-authz-service-design.md`; transport: `docs/superpowers/specs/2026-10-01-connect-vanguard-signed-bundles-design.md`; the Redis gateway view (replaces OPA): `docs/superpowers/specs/2026-10-06-redis-gateway-view-design.md`.
