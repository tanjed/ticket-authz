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

uber **fx** for DI: each package owns a `var Module = fx.Module(...)` in its `module.go` (its providers and lifecycle hooks); `internal/ioc` only lists the modules and returns the `*fx.App`. Add a dependency in its package's module, then include the module in `ioc` if it is new. **Type safety:** every implementation carries a compile-time assertion (`var _ Iface = (*Impl)(nil)`), modules provide implementations as their interface (`fx.As`), and consumers depend on the narrowest interface they need (`grpcapi.AdminBackend`, `bundle.Source`, `idp.Client`, `events.Publisher`); a same-typed dependency is told apart by a tag (`bundle.Tag`). The list order is the start order: migrations (`db`), own manifest (`rbac`), bundle listener, listeners (`server`, last), **chi** for HTTP routing, **proto** as the API source of truth (gRPC + grpc-gateway REST from the same implementation), pgx, goose.

## Invariants (do not break)

1. **The API is defined in proto.** Add or change an endpoint in `proto/`, run `make generate`, implement it in `internal/grpcapi`. No hand-written REST handlers, except the OPA bundle endpoint (binary, long-polled) and `/healthz`.
2. **Two trust zones.** `AdminService` only on the public listeners (trusts `x-bus-*` from the gateway); `InternalService` and bundles only on the internal listeners. Never register a service on the other zone's server or router, and keep the NetworkPolicy in step with the ports.
3. **Every write that changes what OPA sees bumps the bundle revision in the same transaction** (`bump` in `internal/rbac`). A missed bump means gateways keep deciding from stale data.
4. **Tenant scope.** Every role, member and invitation query is scoped by the caller's `company_id`; `member_roles` has composite foreign keys so a cross-company assignment cannot exist.
5. **Escalation rule.** Nobody creates, edits, deletes, assigns or removes a role whose permissions they don't hold (read fresh from the database, never from the token).
6. **Deny by default.** Unknown or deprecated routes are left out of the catalogue bundle; the policy denies what it does not find.
7. **Domain errors are transport-neutral** (`rbac.Kind` + a stable code); `grpcapi` maps them to gRPC codes with the code as `ErrorInfo.reason`. Don't return gRPC statuses from `rbac`.
8. **The chart never creates secrets.**
9. **Migrations run at boot**, before anything is served (`db.Module`, early in `internal/ioc`). There is no separate migrate command; a migration must be safe to apply while older replicas are still serving (expand, then contract).

## Gotchas

- The catalogue bundle's revision includes a hash of the policy: a policy change reaches OPAs on deploy even though no database row changed.
- Invitations are delivered by the IdP (`../IdP`, `/api/internal/invitations`); if that call fails, the invitation is deleted and the admin gets `UNAVAILABLE`.
- Events are published after commit, best effort (no outbox): a Kafka outage loses them (logged).

## Status

Built: everything in the spec. Verified: rbac Postgres integration tests (before the move to proto/fx), bundle and catalogue unit tests, the fx graph, 20 rego tests, discovery and long polling against a real OPA and APISIX (compose, before the move to proto/fx). **Not yet run:** the server tests (REST and gRPC over Postgres) and the rbac tests after the move; a full login through the IdP with provider claims. The chart has never been installed. Not built: see spec section 13a.
