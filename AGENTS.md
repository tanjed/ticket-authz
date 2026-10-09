# AGENTS.md: Authz

Authorization service for Bus 2.0: permission catalogue, company roles and members, and the gateway view in Redis the APISIX gateway decides from. See README.md; design in `docs/superpowers/specs/`.

## Commands

| Command | Purpose |
|---|---|
| `make tools` | Install pinned buf and protoc plugins into `./bin` |
| `make generate` | Regenerate `api/` from `proto/` (commit the result) |
| `make test` | Go tests (Postgres via testcontainers: needs Docker) |
| `make verify` | lint, test, template |
| `docker compose up -d --build` | Local Authz + Postgres on `shohoz` |

## Stack

uber **fx** for DI: each package owns a `var Module = fx.Module(...)` in its `module.go` (its providers and lifecycle hooks); `internal/ioc` only lists the modules and returns the `*fx.App`. Add a dependency in its package's module, then include the module in `ioc` if it is new. **Type safety:** every implementation carries a compile-time assertion (`var _ Iface = (*Impl)(nil)`), modules provide implementations as their interface (`fx.As`), and consumers depend on the narrowest interface they need (`admin.Backend`, `internalapi.Backend`, `router.Registrar`, `router.Handlers`, `health.Checker`, `rbac.View`, `idp.Client`, `events.Publisher`); health probes are a value group (`health.ProbeGroup`: the package owning a dependency contributes its probe, as `db` does). The list order is the start order: migrations (`db`), own manifest and gateway view rebuild (`rbac`), services registering with the router (`health`, `admin`, `internalapi`), listeners (`server`, last), **chi** for HTTP routing, **proto** as the API source of truth: Connect handlers, one package per proto service (`internal/admin`, `internal/internalapi`, `internal/health`), thin adapters over the business logic in `rbac`, served by **Vanguard** as Connect, gRPC, gRPC-Web and REST on one port per zone (h2c), pgx, goose, **go-redis** for the gateway view.

## Invariants (do not break)

1. **The API is defined in proto.** Add or change an endpoint in `proto/`, run `make generate`, implement it in that service's handler package (`internal/admin`, `internal/internalapi`, `internal/health`); business logic goes in `rbac`, never in a handler. No hand-written REST handlers. Health is `HealthService` (`GET /live`, `GET /ready`: the kubelet's probes).
2. **Two trust zones.** `AdminService` only on the public listener (trusts `X-Bus-*` from the gateway); `InternalService` only on the internal listener; `HealthService` on both. Services register themselves: each handler has a `Register(router.Registrar)` method next to its type that picks its listener, one line, `r.Public(...)`, `r.Internal(...)` or `r.Both(...)`, and its module lists it in `fx.Invoke` (`(*admin.Admin).Register`); `server` loops over what `router` collected (`router.Handlers`), so `server.Module` stays last. Registering after the handlers are built panics. Each zone gets its own Vanguard transcoder; RPC paths go to it untouched, every other path is REST behind `restErrors`. Never wire a service into the other zone, and keep the NetworkPolicy in step with the ports.
3. **Every write that changes what the gateway sees goes through `write` and updates the gateway view after commit** (`internal/rbac/view.go`). `write` holds the `authz.view` advisory lock shared until the Redis update is done; `Rebuild` (every boot) holds it exclusively, so it never overwrites a fresh update. A missed update means the gateway decides from stale data until the next boot. The Redis key layout (`internal/redisview`) is a contract with `../APISIX`: change both together.
4. **Tenant scope.** Every role, member and invitation query is scoped by the caller's `company_id`; `member_roles` has composite foreign keys so a cross-company assignment cannot exist.
5. **Escalation rule.** Nobody creates, edits, deletes, assigns or removes a role whose permissions they don't hold (read fresh from the database, never from the token).
6. **Deny by default.** Unknown or deprecated routes (and deprecated permissions) are left out of the gateway view; the gateway denies what it does not find.
7. **Domain errors are transport-neutral** (`rbac.Kind` + a stable code); handlers map them to Connect codes with `router.Error` (the code becomes `ErrorInfo.reason`). Don't return Connect errors from `rbac`.
8. **The chart never creates secrets.**
9. **Migrations run at boot**, before anything is served (`db.Module`, early in `internal/ioc`). There is no separate migrate command; a migration must be safe to apply while older replicas are still serving (expand, then contract).
10. **Authorization versions are never reused.** `members.authz_version` comes from the global `authz_versions` sequence; a new value on every role assignment change. Never reset it per user.

## Gotchas

- Authz refuses to boot while Redis is unreachable (the boot rebuild); `/ready` fails while Redis or Postgres is down, `/live` never checks them.
- Invitations are delivered by the IdP (`../IdP`, `/api/internal/invitations`); if that call fails, the invitation is deleted and the admin gets `UNAVAILABLE`.
- REST JSON clients get REST; a JSON POST to an RPC path needs `Connect-Protocol-Version: 1` (real Connect clients send it), or Vanguard treats it as REST.
- Local compose needs `../Infra` up first (its Redis, `infra-redis`); Authz restarts until it is.
- Events are published after commit, best effort (no outbox): a Kafka outage loses them (logged).

## Status

Built: everything in the spec, Connect/Vanguard on two ports (2026-10-01), and the Redis gateway view replacing OPA bundles (2026-10-06). Verified: rbac and server tests over Postgres with the view on miniredis (every write's keys, versions, deprecation, the boot rebuild), REST, Connect JSON, gRPC, health, zone isolation, the fx graph. **Not yet run:** Authz against a real Redis on compose; the APISIX plugin reading the replica (`../APISIX`, not built); a full login through the IdP with provider claims. The chart has never been installed. Not built: see spec section 13a.
