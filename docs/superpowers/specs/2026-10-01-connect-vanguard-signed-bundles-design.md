# Connect + Vanguard transport, signed OPA bundles

Date: 2026-10-01. Amends sections 6, 7 and 12 of `2026-09-29-authz-service-design.md`.

## 1. Goal

- Serve every API over Connect, gRPC, gRPC-Web and REST from **one port per trust zone**, instead of separate REST and gRPC ports (four listeners).
- Keep every existing caller working unchanged: the REST paths, snake_case JSON and the `{"error": <reason>, "message"}` error body (the IdP reads `error` and `message`), and APISIX routing to `authz:8080`.
- Build bundles with OPA's own bundle package rather than hand-written tar code, and **sign every bundle**, so a gateway's OPA refuses a bundle that Authz did not produce.

## 2. Transport

| Zone | Port | Serves |
|---|---|---|
| public | `:8080` | `AdminService` (Connect, gRPC, gRPC-Web, REST `/v1/*`), health, reflection |
| internal | `:8081` | `InternalService` (Connect, gRPC, gRPC-Web, REST `/internal/*`), health, reflection, `/bundles/*`, `/healthz` |

- Each listener is a stdlib `http.Server` with HTTP/1.1 and cleartext HTTP/2 (`http.Protocols`, no `x/net/h2c`). TLS ends before Authz.
- The services are Connect handlers (`protoc-gen-connect-go`, `simple` option: handler methods keep the `(ctx, *Req) (*Res, error)` signature). Each zone wraps **only its own service** in a Vanguard transcoder, so the trust zones stay port-separated (invariant 2).
- chi routes by path. `/v1/*` and `/internal/*` go to `restErrors(transcoder)`. The RPC path (`/bus.authz.v1.<Service>/*`) goes to the transcoder untouched. `grpc.health.v1.Health` and reflection (v1 and v1alpha, listing only the zone's service) go directly to their Connect handlers.
- JSON: proto field names, unpopulated fields emitted, unknown fields refused. This applies to both Vanguard's REST codec and Connect's `json` codec. A REST body that does not decode is `INVALID_ARGUMENT` (Vanguard's default would be `UNKNOWN`).
- Panics become `INTERNAL` on every protocol (`connect.WithRecover`), plus chi's `Recoverer`.
- The `x-bus-*` caller now comes from request headers (`connect.CallInfoForHandlerContext`). REST, Connect and gRPC metadata all arrive as headers. The rule is unchanged: exactly one value or it isn't trusted.
- Errors: `rpcapi` returns `connect.Error` with an `ErrorInfo{reason, domain: authz.bus}` detail. Vanguard writes REST errors as `google.rpc.Status` JSON, and `restErrors` rewrites a non-2xx JSON response into `{"error": <reason or code name>, "message"}` with the same status. It holds back flushes while capturing, so a 200 is never committed early. Connect and gRPC errors keep their native format.
- The removed pieces: `grpc-go` server, grpc-gateway runtime, ports 9090/9091, `AUTHZ_*_GRPC_ADDR`. The `protoc-gen-openapiv2` generator stays (a build tool, not a runtime dependency).

## 3. Signed bundles

- `bundle.Build` fills an OPA `bundle.Bundle` (data, manifest with revision and roots, the policy as a module). It signs it with `GenerateSignature` (RS256, key id) and writes it with `bundle.NewWriter(...).DisableFormat(true)`, so the policy ships byte for byte. The revision (and ETag) scheme is unchanged.
- The discovery bundle tells OPA to verify every bundle it lists (`signing: {keyid}`). OPA's boot config holds the public key and verifies the discovery bundle itself.
- No unsigned mode. `AUTHZ_BUNDLE_SIGNING_KEY_FILE` and `AUTHZ_BUNDLE_SIGNING_KEY_ID` are required. The key is parsed at boot, and the policy is parsed at boot (`ParsePolicies`), so a bad key or a broken policy fails the start rather than every gateway.
- The serving side (ETag, `Prefer: wait=N` long poll, Postgres NOTIFY hub) stays hand-written: OPA ships no bundle server, and S3 or OCI would lose the push on NOTIFY.

Deployment:
- Authz chart: Secret `authz-bundle-signing` (key `private.pem`), referenced, never created. `bundleSigning.keyId` is required.
- `../APISIX` chart: `opa.bundleSigning.{keyId, publicKey}`, rendered into OPA's `keys` and `discovery.signing`.
- Compose: a one-shot `authz-dev-keys` service creates `dev-keys/` (gitignored). APISIX's OPA loads the public half with `--set-file=keys.authz-dev.key=...`.
- Rotation: add the new public key to OPA under a new id, then switch Authz's Secret and key id.

## 4. Chart

Deployment and Service: ports `public` 8080 and `internal` 8081 (`appProtocol: kubernetes.io/h2c`). The liveness probe is `grpc` on 8081 (the gRPC health service over h2c); readiness stays `/healthz`. The NetworkPolicy allows 8080 from the gateway and 8081 in-cluster.

## 5. Testing

- Server tests over Postgres on real h2c sockets:
  - REST flow and error shape
  - gRPC via a Connect client (`WithGRPC`): reasons, caller headers, a duplicated header refused
  - Connect JSON errors are not rewritten
  - zone isolation for REST and RPC paths
  - health on both listeners
- Bundle tests: every bundle is read back with OPA's reader and signature verification. A tampered `data.json`, a wrong key and a missing signer are refused. Bad keys are rejected, and the shipped policy parses.
- Compose, end to end:
  - every protocol on the real ports
  - APISIX's OPA verifies and activates the signed bundles and decides requests
  - an OPA with the wrong key refuses discovery
  - a manifest change reaches OPA by long poll
