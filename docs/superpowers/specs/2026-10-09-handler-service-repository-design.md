# Handler / Service / Repository layers

Date: 2026-10-09. Status: approved in conversation; implementation follows directly (no separate plan).

## Goal

Split Authz's code into three layers, each in its own folder, with small single-purpose units:

- a template other Bus 2.0 Go services can copy,
- readable files with one responsibility each,
- services testable without Postgres, storage swappable behind interfaces.

No behaviour changes: every endpoint, error code, gateway-view write and event stays as it is.

## Layout

```
internal/
  handler/                 transport only: proto <-> service, error mapping
    admin/                 AdminService     (public listener)
    internalapi/           InternalService  (internal listener)
    health/                HealthService    (both listeners)
  service/                 business rules; no SQL, no proto
  repository/              SQL only; implements the ports service declares
  health/                  Checker + probes
  router/ server/ db/ redisview/ events/ idp/ config/ ioc/   (unchanged roles)
```

`internal/rbac` is removed: its rules go to `service`, its SQL to `repository`.

## Dependency direction (SOLID D)

```
handler/*  ->  service  <-  repository
                  ^
              redisview (implements service.GatewayView)
```

`service` owns the domain types and declares the interfaces it needs (ports): one repository
interface per aggregate, a factory type per repository, `UnitOfWork`, `GatewayView`. `repository`
and `redisview` import `service` and implement them. `service` never imports `repository` (it would
be an import cycle, and it would point the dependency the wrong way). `ioc` wires them.

`service` imports `db` only for `db.Querier` (the pool or a transaction), which it passes through
to repository factories without using it.

## Service layer (`internal/service`)

One service per aggregate, each in its own file, each depending only on what it uses:

| Service | Methods | Uses |
|---|---|---|
| `CatalogueService` | `ApplyManifest`, `Permissions` | UoW, `CatalogueRepo`, `RoleRepo` (view), `GatewayView` |
| `CompanyService` | `Create`, `SetStatus`, `Claims` | UoW, `CompanyRepo`, `RoleRepo`, `MemberRepo`, `GatewayView`, events |
| `RoleService` | `List`, `Get`, `Create`, `Update`, `Delete` | UoW, `RoleRepo`, `MemberRepo` (power), `CatalogueRepo` (live keys), `GatewayView`, events |
| `MemberService` | `List`, `SetRoles`, `Remove` | UoW, `MemberRepo`, `RoleRepo`, `GatewayView`, events |
| `InvitationService` | `Create`, `List`, `Get`, `Accept` | UoW, `InvitationRepo`, `MemberRepo`, `RoleRepo`, `CompanyRepo`, IdP, `GatewayView`, events |
| `ViewService` | `Rebuild` | UoW, `CatalogueRepo`, `RoleRepo`, `CompanyRepo`, `MemberRepo`, `GatewayView` |

Files: one per service (`catalogue.go`, `company.go`, `role.go`, `member.go` with the last-admin
guard, `invitation.go` with the derived status, `rebuild.go`); pure rules in `power.go` (escalation
rule, `callerPower`) and `input.go` (validation); domain types in `model.go`; errors (`Kind`,
`Error`, transport-neutral, invariant 7, plus `ErrNotFound` / `ErrDuplicate`) in `errors.go`; ports
in `ports.go`; gateway view interface and snapshot types in `view.go`.

One deliberate difference from `rbac`: creating an invitation now runs through `UnitOfWork.Write`
(no projection), so it takes the view lock shared like every other write.

The boot hooks (seed Authz's own manifest, rebuild the gateway view) live in `service/module.go`.

## Unit of Work

```go
type UnitOfWork interface {
	// Write: shared authz.view lock, one transaction, commit, then project on the pool
	// (5 s timeout; a failure is logged, the next boot's Rebuild repairs the view).
	Write(ctx context.Context, fn func(ctx context.Context, q db.Querier) error,
		project func(ctx context.Context, q db.Querier) error) error
	// Read: the pool, no lock, no transaction.
	Read(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
	// Snapshot: exclusive authz.view lock, repeatable-read read-only transaction (Rebuild only).
	Snapshot(ctx context.Context, fn func(ctx context.Context, q db.Querier) error) error
}
```

Each service binds the repositories it needs per call, from factories fx injects:

```go
type roleRepos struct { roles RoleRepo; members MemberRepo; catalogue CatalogueRepo }
func (s *RoleService) bind(q db.Querier) roleRepos { ... }
```

Generic helpers `write[R]`, `read[R]` adapt the UoW to the bound struct. Invariant 3 is enforced
in one place: every gateway-visible write goes through `UnitOfWork.Write`. Events stay published by
the service after `Write` returns (best effort, as today).

## Repository layer (`internal/repository`)

One file per aggregate, a pgx implementation of the service port, built from a `db.Querier`:
`catalogue.go`, `company.go`, `role.go`, `member.go`, `invitation.go`; `uow.go` (the UnitOfWork,
advisory locks), `errors.go` (pgx errors to `service.ErrNotFound` / `service.ErrDuplicate`).
Every role, member and invitation query takes `companyID` explicitly (invariant 4). Row locks are
explicit methods (`Lock`).

`repository.Module` (fx) provides the UnitOfWork and every repository factory
(`service.RoleRepoFactory` and the rest).

## Handler layer (`internal/handler/*`)

Thin adapters: decode proto, call a service, encode proto, map errors with `router.Error`. Each
handler depends on narrow interfaces it declares over the services (`admin.Roles`, ...), and
registers itself on its listener (`Register`, invoked by its fx module).

## Errors

Unchanged: services return `service.Error` (Kind + stable code); repositories return raw errors or
`service.ErrNotFound` / `service.ErrDuplicate`, which services turn into domain errors;
`router.Error` maps to Connect codes.

## Testing

- The `rbac` integration tests move to `internal/service` (real repositories over testcontainers
  Postgres, gateway view on miniredis), unchanged in what they assert.
- Unit tests without Postgres for the pure rules (escalation, input validation, invitation
  status).
- `server` and `ioc` tests keep passing.

## Out of scope

Behaviour changes, new endpoints, a transactional outbox, a generic CRUD repository (rejected:
the aggregates are not plain rows).
