package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/handler/admin"
	healthhandler "github.com/tanjed/bus2/authz/internal/handler/health"
	"github.com/tanjed/bus2/authz/internal/handler/internalapi"
	"github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/internal/redisview"
	"github.com/tanjed/bus2/authz/internal/repository"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service"
	"github.com/tanjed/bus2/authz/internal/testdb"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	var stop func()
	var err error
	pool, stop, err = testdb.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "postgres:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

var _ idp.Client = noIdP{}

type noIdP struct{}

func (noIdP) IdentityByPhone(context.Context, string) (string, error) { return "", nil }
func (noIdP) SendInvitation(context.Context, idp.Invitation) error    { return nil }

type stack struct {
	h handlers
	// The handlers on real sockets, cleartext HTTP/2 (gRPC needs it), and a client that speaks it.
	publicURL, internalURL string
	client                 *http.Client
}

// newStack builds the real handlers over a fresh database and serves them on local sockets.
func newStack(t *testing.T) stack {
	t.Helper()
	testdb.Reset(t, pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	view := &redisview.Redis{C: redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})}
	uow, ev := repository.NewUnitOfWork(pool, log), events.Log{Logger: log}
	cat, comp, role, mem, inv := repository.NewCatalogue, repository.NewCompany, repository.NewRole, repository.NewMember, repository.NewInvitation
	catalogue := service.NewCatalogueService(uow, view, cat, role)
	invitations := service.NewInvitationService(uow, view, ev, noIdP{}, time.Hour, inv, mem, role, comp)
	h := build(t, log,
		admin.New(catalogue, service.NewRoleService(uow, view, ev, role, mem, cat), service.NewMemberService(uow, view, ev, mem, role), invitations, log),
		internalapi.New(catalogue, service.NewCompanyService(uow, view, ev, comp, role, mem), invitations, log),
		healthhandler.NewHandler(health.New([]health.Probe{{Name: "db", Check: pool.Ping}}), log))
	serve := func(h http.Handler) string {
		srv := httptest.NewUnstartedServer(h)
		srv.Config = newHTTPServer(h, 0)
		srv.Start()
		t.Cleanup(srv.Close)
		return srv.URL
	}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return stack{h: h, publicURL: serve(h.public), internalURL: serve(h.internal),
		client: &http.Client{Transport: &http.Transport{Protocols: protocols}}}
}

// handlers are the two listeners' handlers, built without opening any socket.
type handlers struct {
	public, internal http.Handler
}

// build has each service register itself, as the modules do, and builds each listener's handler.
func build(t *testing.T, log *slog.Logger, a *admin.Admin, in *internalapi.Internal, h *healthhandler.Handler) handlers {
	t.Helper()
	r := router.New(log)
	a.Register(r)
	in.Register(r)
	h.Register(r)
	public, internal, err := r.Handlers()
	require.NoError(t, err)
	return handlers{public: public, internal: internal}
}

func do(t *testing.T, h http.Handler, method, path, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out), rec.Body.String())
	}
	return rec.Code, out
}

const manifest = `{
	"permissions": [{"key": "order:read", "consumer": true}, {"key": "order:cancel"}],
	"routes": [{"name": "order.read", "permission": "order:read"}, {"name": "order.health", "public": true}]
}`

func TestREST_InternalFlow(t *testing.T) {
	s := newStack(t)
	code, body := do(t, s.h.internal, "PUT", "/internal/v1/manifests/order", manifest, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, map[string]any{"service": "order", "permissions": float64(2), "routes": float64(2), "changed": true}, body,
		"snake_case JSON, empty fields emitted")

	code, body = do(t, s.h.internal, "PUT", "/internal/v1/manifests/order", `{"permissions": [{"key": "a:b", "consumers": true}]}`, nil)
	require.Equal(t, http.StatusBadRequest, code, "unknown fields are refused")
	require.Equal(t, "invalid_argument", body["error"])

	code, body = do(t, s.h.internal, "POST", "/internal/v1/companies", `{"name": "Acme", "admin_sub": "u1"}`, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, true, body["created"])

	code, body = do(t, s.h.internal, "GET", "/internal/v1/subjects/u1/claims", "", nil)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, body["company_id"], body["company_id"])
	require.Len(t, body["roles"], 1)

	code, body = do(t, s.h.internal, "GET", "/internal/v1/subjects/nobody/claims", "", nil)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, "not_a_member", body["error"], "the domain reason survives to REST")

	code, _ = do(t, s.h.internal, "GET", "/ready", "", nil)
	require.Equal(t, http.StatusOK, code)
	code, _ = do(t, s.h.internal, "GET", "/v1/roles", "", nil)
	require.Equal(t, http.StatusNotFound, code, "the admin API is not on the internal listener")
}

func TestREST_AdminAPI(t *testing.T) {
	s := newStack(t)
	do(t, s.h.internal, "PUT", "/internal/v1/manifests/order", manifest, nil)
	_, body := do(t, s.h.internal, "POST", "/internal/v1/companies", `{"name": "Acme", "admin_sub": "u1"}`, nil)
	admin := map[string]string{"X-Bus-Subject": "u1", "X-Bus-Company-Id": body["company_id"].(string), "X-Bus-User-Type": "provider"}

	code, body := do(t, s.h.public, "POST", "/v1/roles", `{"name": "Clerk", "permissions": ["order:read"]}`, admin)
	require.Equal(t, http.StatusOK, code, body)
	role := body["role"].(map[string]any)
	require.Equal(t, "Clerk", role["name"])
	require.Equal(t, false, role["grants_all"])

	code, body = do(t, s.h.public, "GET", "/v1/roles", "", admin)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body["roles"], 2)
	var protectedID string
	for _, r := range body["roles"].([]any) {
		if r.(map[string]any)["protected"] == true {
			protectedID = r.(map[string]any)["id"].(string)
		}
	}
	code, body = do(t, s.h.public, "PUT", "/v1/roles/"+protectedID, `{"name": "Boss"}`, admin)
	require.Equal(t, http.StatusBadRequest, code)
	require.Equal(t, "protected_role", body["error"])

	consumer := map[string]string{"X-Bus-Subject": "u1", "X-Bus-User-Type": "consumer"}
	code, body = do(t, s.h.public, "GET", "/v1/roles", "", consumer)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, "provider_only", body["error"])

	code, _ = do(t, s.h.public, "PUT", "/internal/v1/manifests/order", manifest, nil)
	require.Equal(t, http.StatusNotFound, code, "the internal API is not on the public listener")
}

// caller is a client context carrying the gateway's caller headers (gRPC metadata on the wire).
func caller(ctx context.Context, kv ...string) context.Context {
	ctx, info := connect.NewClientContext(ctx)
	for i := 0; i < len(kv); i += 2 {
		info.RequestHeader().Add(kv[i], kv[i+1])
	}
	return ctx
}

func TestGRPC_BothServices(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	internal := authzv1connect.NewInternalServiceClient(s.client, s.internalURL, connect.WithGRPC())
	admin := authzv1connect.NewAdminServiceClient(s.client, s.publicURL, connect.WithGRPC())

	_, err := internal.ApplyManifest(ctx, &authzv1.ApplyManifestRequest{
		Service:     "order",
		Permissions: []*authzv1.ManifestPermission{{Key: "order:read"}},
		Routes:      []*authzv1.ManifestRoute{{Name: "order.read", Permission: "order:read"}},
	})
	require.NoError(t, err)
	co, err := internal.CreateCompany(ctx, &authzv1.CreateCompanyRequest{Name: "Acme", AdminSub: "u1"})
	require.NoError(t, err)

	_, err = internal.GetClaims(ctx, &authzv1.GetClaimsRequest{Sub: "nobody"})
	require.Equal(t, connect.CodeNotFound, connect.CodeOf(err))
	require.Equal(t, "not_a_member", router.Reason(err), "the domain reason survives to gRPC")

	md := []string{"x-bus-subject", "u1", "x-bus-company-id", co.GetCompanyId(), "x-bus-user-type", "provider"}
	roles, err := admin.ListRoles(caller(ctx, md...), &authzv1.ListRolesRequest{})
	require.NoError(t, err)
	require.Len(t, roles.GetRoles(), 1)
	require.True(t, roles.GetRoles()[0].GetGrantsAll())

	_, err = admin.ListRoles(ctx, &authzv1.ListRolesRequest{})
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err), "no caller metadata")

	// Two values for one key: trust neither.
	_, err = admin.ListRoles(caller(ctx, append(md, "x-bus-company-id", "other")...), &authzv1.ListRolesRequest{})
	require.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))

	// Trust zones: neither service answers on the other's listener.
	_, err = authzv1connect.NewAdminServiceClient(s.client, s.internalURL, connect.WithGRPC()).ListRoles(caller(ctx, md...), &authzv1.ListRolesRequest{})
	require.Error(t, err, "the admin API is not on the internal listener")
	_, err = authzv1connect.NewInternalServiceClient(s.client, s.publicURL, connect.WithGRPC()).GetClaims(ctx, &authzv1.GetClaimsRequest{Sub: "u1"})
	require.Error(t, err, "the internal API is not on the public listener")
}

func TestConnect_JSONKeepsItsOwnErrors(t *testing.T) {
	s := newStack(t)
	// Connect protocol, JSON: what buf curl or a browser client sends.
	connectJSON := map[string]string{"Content-Type": "application/json", "Connect-Protocol-Version": "1"}
	code, body := do(t, s.h.internal, "POST", "/bus.authz.v1.InternalService/GetClaims", `{"sub": "nobody"}`, connectJSON)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, "not_found", body["code"], "a Connect error, not rewritten into the REST shape")
	require.NotContains(t, body, "error")

	code, _ = do(t, s.h.internal, "POST", "/bus.authz.v1.AdminService/ListRoles", `{}`, connectJSON)
	require.Equal(t, http.StatusNotFound, code, "the admin API is not on the internal listener")

	// Connect client, JSON codec: snake_case, as REST.
	internal := authzv1connect.NewInternalServiceClient(s.client, s.internalURL, connect.WithProtoJSON())
	res, err := internal.ApplyManifest(context.Background(), &authzv1.ApplyManifestRequest{Service: "order"})
	require.NoError(t, err)
	require.Equal(t, "order", res.GetService())
}

func TestHealth(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	for _, url := range []string{s.publicURL, s.internalURL} {
		client := authzv1connect.NewHealthServiceClient(s.client, url, connect.WithGRPC())
		_, err := client.Live(ctx, &authzv1.LiveRequest{})
		require.NoError(t, err, url)
		res, err := client.Ready(ctx, &authzv1.ReadyRequest{})
		require.NoError(t, err, url)
		require.Equal(t, []string{"db"}, res.GetComponents())
	}
	for _, h := range []http.Handler{s.h.public, s.h.internal} {
		code, _ := do(t, h, "GET", "/live", "", nil)
		require.Equal(t, http.StatusOK, code)
		code, body := do(t, h, "GET", "/ready", "", nil)
		require.Equal(t, http.StatusOK, code)
		require.Equal(t, []any{"db"}, body["components"])
	}
}

// A failed probe: not ready (503 on REST, UNAVAILABLE on RPC, the message naming the component
// without its error), but still live, so the kubelet does not restart pods over a database outage.
func TestHealth_Unavailable(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	down := health.New([]health.Probe{{Name: "db", Check: func(context.Context) error { return fmt.Errorf("dial tcp 10.0.0.5:5432: refused") }}})
	h := build(t, log, &admin.Admin{}, &internalapi.Internal{}, healthhandler.NewHandler(down, log))

	code, body := do(t, h.internal, "GET", "/ready", "", nil)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, map[string]any{"error": "unhealthy", "message": "unavailable: db"}, body)

	connectJSON := map[string]string{"Content-Type": "application/json", "Connect-Protocol-Version": "1"}
	code, body = do(t, h.public, "POST", "/bus.authz.v1.HealthService/Ready", `{}`, connectJSON)
	require.Equal(t, http.StatusServiceUnavailable, code)
	require.Equal(t, "unavailable", body["code"])

	code, _ = do(t, h.internal, "GET", "/live", "", nil)
	require.Equal(t, http.StatusOK, code)
}
