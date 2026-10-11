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
    health/                HealthService    (internal listener)
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

Thin adapters: decode proto, call a service, encode proto, return errors untouched. Each
handler depends on narrow interfaces it declares over the services (`admin.Roles`, ...), and
is declared on its listener by its fx module (`router.Public(authzv1connect.NewAdminServiceHandler)`, `router.Internal`), which adds it to the `vanguard_services` group the router builds from.

## Errors

Unchanged: services return `service.Error` (Kind + stable code); repositories return raw errors or
`service.ErrNotFound` / `service.ErrDuplicate`, which services turn into domain errors;
the error interceptor in `router` (one place, every service) maps them to Connect codes.

## Testing

- The `rbac` integration tests move to `internal/service` (real repositories over testcontainers
  Postgres, gateway view on miniredis), unchanged in what they assert.
- Unit tests without Postgres for the pure rules (escalation, input validation, invitation
  status).
- `router` (formerly `server`) and `ioc` tests keep passing.

## Out of scope

Behaviour changes, new endpoints, a transactional outbox, a generic CRUD repository (rejected:
the aggregates are not plain rows).

## Revision: one package and one fx module per service and repository

Supersedes the single `service` and `repository` packages above.

```
internal/
  domain/          model.go errors.go view.go ports.go   types, errors, GatewayView, ports
  service/
    access/        Power, CallerPower (the escalation rule, shared)
    catalogue/     service.go module.go (seeds Authz's own manifest on start)
    company/       service.go module.go
    role/          service.go input.go module.go
    member/        service.go guard.go module.go
    invitation/    service.go input.go status.go module.go
    view/          service.go module.go (rebuilds the gateway view on start)
    module.go      service.Module = fx.Options(every service module; catalogue before view)
  repository/
    uow/           the UnitOfWork + module
    internal/pgerr pgx errors to domain.ErrNotFound / domain.ErrDuplicate
    catalogue/ company/ role/ member/ invitation/   repository.go module.go
    module.go      repository.Module = fx.Options(every repository module)
```

- Each service is `<pkg>.Service` with `<pkg>.New`; each repository `<pkg>.Repository` with
  `<pkg>.New`, provided as its `domain.<Name>RepoFactory`.
- `service/*` and `repository/*` import `internal/domain`, never each other.
- Unit tests live next to each rule (`access`, `role`, `member`, `invitation`, `company`) and need no
  database; the integration suite stays in `internal/service` and builds the services through the
  real fx modules.

## Revision 2: transaction in the context, no domain package

Supersedes the factories, `bind`, and `internal/domain` above.

```
internal/
  apperror/        Kind, Error, Fail, NotFound, Escalation, As; ErrNotFound, ErrDuplicate, FromPG;
                   Interceptor (the one place errors become Connect codes), REST (error bodies)
  gateway/         View (what services write through), RoleView, Snapshot; Redis implements View
  db/              WritePool, ReadPool, Querier, migrations
    uow/           UnitOfWork: Write / Read / Snapshot put the transaction (or the replica) in ctx;
                   Q(ctx) is what repositories query on. Provided as Transactor and Querier.
  repository/<name>/   Repository (injected once, takes uow.Querier), its row types, its Repo
  service/<name>/      imports repositories directly; s.uow.Write(ctx, func(ctx) error {...}, project)
    access/            Caller, Power, CallerPower, ValidSubject
```

- Repositories are singletons; the transaction travels in the context, so services never build
  repositories per call. Call repositories only inside `Write`, `Read` or `Snapshot`; outside,
  `Q(ctx)` is the primary, outside any transaction.
- Types live with their owner: row types in each repository package (`rolerepo.Role`), request and
  result types in each service package (`role.Input`, `catalogue.Result`, `company.Claims`), with
  aliases where a handler needs a repository type (`role.Role`).
- Services depend on `uow.Transactor`, each repository's `Repo` and `gateway.View`; repositories on
  `uow.Querier`.

## Revision 3: one `UnitOfWork` method

`uow.Transactor` is `UnitOfWork(ctx, timeout, fn)` plus `Snapshot(ctx, timeout, fn)` (rebuild only):

- `UnitOfWork` begins a transaction on the primary, takes the view lock shared for the
  transaction (`pg_advisory_xact_lock_shared`), runs `fn` with the transaction in the context,
  and commits; any error, panic or elapsed deadline rolls back. Inside another unit of work it
  joins it (`InTransaction`), and the outermost one commits.
- No `Read`: outside a unit of work `Q(ctx)` is the read replica.
- No after-commit callback: after `UnitOfWork` returns nil, the service calls
  `gateway.Update(ctx, log, uow, fn)`, which runs `fn` in its own short unit of work (primary,
  view lock held while Redis is written) and logs a failure instead of returning it.
- `Snapshot` takes the view lock exclusively in a repeatable-read, read-only transaction; the
  rebuild replaces Redis inside it, so the lock covers the Redis write.

## Revision 4: publish on change, no resync

`internal/gateway` became `internal/cache`: a `Publisher` that writes the same keys (routes,
consumer, company status, role permissions, user authorization version) whenever they change.
Gone: the `authz.view` advisory lock, `uow.Snapshot`, the boot rebuild (`service/view`,
`Replace`), and the repository queries only it used. A service reads what it publishes inside its
unit of work and publishes after commit (best effort, failures logged). Accepted: no resync (a
missed publish or a flushed Redis stays stale until the entity changes again) and no ordering
between concurrent writes to the same key.

Then, the same day: the boot resync is back without its lock (`service/resync`, after the
catalogue seed): it reads the whole state from the primary in a unit of work and replaces Redis
(`cache.Publisher.Replace`, which deletes keys of what no longer exists). A failed resync fails the
boot. Still accepted: no ordering between concurrent writes, or a write during the resync.
