# AGENTS.md: Authz

Authorization service for Bus 2.0: permission catalogue, company roles and members, OPA bundles for the APISIX gateway. See README.md; design in `docs/superpowers/specs/`.

## Commands

| Command | Purpose |
|---|---|
| `make tools` | Install pinned buf and protoc plugins into `./bin` |
| `make generate` | Regenerate `api/` from `proto/` (commit the result) |
| `make test` | Go tests (Postgres via testcontainers: needs Docker) |
| `make test-policy` | `opa test` for `policy/` |
| `make verify` | lint, test, test-policy, template |
| `docker compose up -d --build` | Local Authz + Postgres on `shohoz` |

## Stack

uber **fx** for DI: each package owns a `var Module = fx.Module(...)` in its `module.go` (its providers and lifecycle hooks); `internal/ioc` only lists the modules and returns the `*fx.App`. Add a dependency in its package's module, then include the module in `ioc` if it is new. **Type safety:** every implementation carries a compile-time assertion (`var _ Iface = (*Impl)(nil)`), modules provide implementations as their interface (`fx.As`), and consumers depend on the narrowest interface they need (`rpcapi.AdminBackend`, `health.Checker`, `bundle.Source`, `idp.Client`, `events.Publisher`); a same-typed dependency is told apart by a tag (`bundle.Tag`); health probes are a value group (`health.ProbeGroup`: the package owning a dependency contributes its probe, as `db` does). The list order is the start order: migrations (`db`), own manifest (`rbac`), bundle listener, listeners (`server`, last), **chi** for HTTP routing, **proto** as the API source of truth: Connect handlers (`internal/rpcapi`), served by **Vanguard** as Connect, gRPC, gRPC-Web and REST on one port per zone (h2c), pgx, goose, OPA's **bundle package** for signed bundles.

## Invariants (do not break)

1. **The API is defined in proto.** Add or change an endpoint in `proto/`, run `make generate`, implement it in `internal/rpcapi`. No hand-written REST handlers, except OPA's bundle download `/bundles/*` (ETag, long poll, 304: no RPC can speak it); `BundleService` shows the same bundles over RPC. Health is `HealthService` (`GET /healthz` is its REST path).
2. **Two trust zones.** `AdminService` only on the public listener (trusts `X-Bus-*` from the gateway); `InternalService`, `BundleService` and `/bundles/*` only on the internal listener; `HealthService` on both. Every service and route is wired in one function, `wire` (`internal/server/routes.go`): one line each, `public.Service(...)`, `internal.Service(...)`, `both.Service(...)`, `internal.Handle(...)`. Each zone gets its own Vanguard transcoder; RPC paths go to it untouched, every other path is REST behind `restErrors`. Never wire a service into the other zone, and keep the NetworkPolicy in step with the ports.
3. **Every write that changes what OPA sees bumps the bundle revision in the same transaction** (`bump` in `internal/rbac`). A missed bump means gateways keep deciding from stale data.
4. **Tenant scope.** Every role, member and invitation query is scoped by the caller's `company_id`; `member_roles` has composite foreign keys so a cross-company assignment cannot exist.
5. **Escalation rule.** Nobody creates, edits, deletes, assigns or removes a role whose permissions they don't hold (read fresh from the database, never from the token).
6. **Deny by default.** Unknown or deprecated routes are left out of the catalogue bundle; the policy denies what it does not find.
7. **Domain errors are transport-neutral** (`rbac.Kind` + a stable code); `rpcapi` maps them to Connect codes with the code as `ErrorInfo.reason`. Don't return Connect errors from `rbac`.
8. **The chart never creates secrets.**
9. **Migrations run at boot**, before anything is served (`db.Module`, early in `internal/ioc`). There is no separate migrate command; a migration must be safe to apply while older replicas are still serving (expand, then contract).
10. **Bundles are always signed.** No unsigned mode: Authz refuses to boot without its signing key, and the gateway's OPA refuses unverified bundles.

## Gotchas

- The catalogue bundle's revision includes a hash of the policy: a policy change reaches OPAs on deploy even though no database row changed.
- Invitations are delivered by the IdP (`../IdP`, `/api/internal/invitations`); if that call fails, the invitation is deleted and the admin gets `UNAVAILABLE`.
- REST JSON clients get REST; a JSON POST to an RPC path needs `Connect-Protocol-Version: 1` (real Connect clients send it), or Vanguard treats it as REST.
- Local compose creates `dev-keys/` (gitignored) on first start; `../APISIX` mounts its public half.
- Events are published after commit, best effort (no outbox): a Kafka outage loses them (logged).

## Status

Built: everything in the spec, plus Connect/Vanguard on two ports and signed bundles (2026-10-01). Verified: rbac and server tests over Postgres (REST, Connect JSON, gRPC, health, zone isolation), bundle tests (signatures checked with OPA's reader, tampering and a wrong key refused), catalogue unit tests, the fx graph, 20 rego tests; on compose, every protocol on the real ports, and a real OPA verifying and activating signed bundles through APISIX (wrong key refused, a manifest change pushed by long poll). **Not yet run:** a full login through the IdP with provider claims. The chart has never been installed. Not built: see spec section 13a.
