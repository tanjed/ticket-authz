# Redis gateway view (replaces OPA bundles)

Date: 2026-10-06. Supersedes the OPA parts of `2026-09-29-authz-service-design.md` and `2026-10-01-connect-vanguard-signed-bundles-design.md`.

## Goal

The gateway decides every request from Redis instead of OPA bundles. Authz writes the Redis master; APISIX reads a replica. Role and permission changes apply at the gateway as soon as Authz commits them: no bundle fan-out, no long polls.

## Decisions

- **Redis is platform-provided** (`../Infra` locally). Authz only gets `AUTHZ_REDIS_URL` (the master), from a pre-created Secret in the chart.
- **Postgres stays the source of truth.** Redis is a projection of it, the gateway view.
- **Written after commit** (no outbox): each write updates the keys it changed, read back from Postgres after the commit. A failed Redis write is logged; the request still succeeds (the data is committed).
- **Rebuilt whole at boot**, after the own-manifest seed: every key written, orphan `authz:*` keys deleted. This heals a missed write and fills an empty Redis. Authz refuses to boot if Redis is unreachable. Readiness (`/ready`) checks Redis too.
- **No rebuild/write race:** every write holds the Postgres advisory lock `authz.view` shared, from its transaction until its Redis write is done; the rebuild holds it exclusively. A rebuild on one replica can never overwrite a write another replica just projected with an older snapshot. Writes wait for the rebuild (milliseconds).
- **Stale tokens are rejected** (option A): when the JWT's `authz_version` differs from Redis, the gateway answers `401 token_stale`; the client refreshes and the IdP calls `GetClaims` for the new roles and version.

## Key contract (the gateway reads these)

| Key | Type | Content |
|---|---|---|
| `authz:routes` | HASH | APISIX route name → permission key, or `public`. Unknown and deprecated routes (or routes whose permission is deprecated) are absent: denied. |
| `authz:consumer` | SET | consumer permission keys (live only) |
| `authz:company:<cid>` | HASH | `status` = `active` / `suspended` |
| `authz:company:<cid>:role:<rid>` | HASH | live permission → `1`; a `grants_all` role holds `*`. Absent when the role has no permission. |
| `authz:user:<sub>:version` | STRING | the member's authorization version |

A key is always replaced whole (`DEL` then write, in one `MULTI`), so a reader never sees half of it.

## Authorization version

- `members.authz_version bigint`, defaulting to `nextval('authz_versions')`: one global sequence, so a version is never reused (a user removed from company A and invited to B never matches an old A token).
- New value on: company creation (the admin), invitation accept, `SetMemberRoles`.
- `RemoveMember` deletes `authz:user:<sub>:version`: missing counts as stale.
- Role permission edits and company suspension do not change versions: the gateway reads role permissions and company status live.
- `GetClaims` returns `authz_version`; the IdP puts it in the access token.

## Gateway decision (`../APISIX`, plugin `bus-authz`, `chart/files/bus-authz.lua`)

```
perm = HGET authz:routes <route name>          absent: 403 unknown route; "public": allow
verify the JWT (JWKS, issuer, audience)        fail: 401
consumer: SISMEMBER authz:consumer perm        allow, else 403
provider:
  GET authz:user:<sub>:version != jwt.authz_version, or absent: 401 token_stale
  HGET authz:company:<cid> status != active:   403
  any jwt role: HEXISTS authz:company:<cid>:role:<rid> perm, or "*": allow, else 403
```

## What is written when

| Write | Keys |
|---|---|
| ApplyManifest (changed) | `authz:routes`, `authz:consumer`, every role (a deprecated permission leaves every role holding it) |
| CreateCompany | company, its admin role, the admin's version |
| SetCompanyStatus | company |
| CreateRole, UpdateRole | that role |
| DeleteRole | that role deleted (only possible while unassigned) |
| SetMemberRoles, AcceptInvitation | the member's version |
| RemoveMember | the member's version deleted |

## The IdP (`../IdP`)

Consent puts `authz_version` (a number) in a provider's access token. Hydra's `oauth2.token_hook` (`/api/internal/token-hook`) puts fresh `company_id`, `roles` and `authz_version` in every provider refresh, and refuses the refresh (403) when the member left the company or it is suspended. Without the hook Hydra would copy the old claims into the refreshed token, and a `token_stale` token could never be mended by a refresh.

## Removed

The OPA bundle server (`internal/bundle`), the policy (`policy/`), `BundleService`, `/bundles/*`, bundle signing (config, chart Secret, compose dev keys), the bundle revision bump and its `NOTIFY` listener, `make test-policy`. The `bundle_revisions` table (removed from the initial migration: nothing is live yet).

## Testing

Redis via miniredis in tests: the key contract per write, the boot rebuild (orphans deleted), versions (new on assignment, never reused, deleted on removal), `GetClaims` returning the version, `/ready` failing without Redis.
