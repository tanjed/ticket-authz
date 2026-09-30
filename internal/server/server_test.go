package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/bundle"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/grpcapi"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/internal/rbac"
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

type noIdP struct{}

func (noIdP) IdentityByPhone(context.Context, string) (string, error) { return "", nil }
func (noIdP) SendInvitation(context.Context, idp.Invitation) error    { return nil }

type stack struct {
	h                        handlers
	publicGRPC, internalGRPC *grpc.ClientConn
}

// newStack builds the real handlers over a fresh database, gRPC on in-memory listeners.
func newStack(t *testing.T) stack {
	t.Helper()
	testdb.Reset(t, pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := rbac.New(pool, events.Log{Logger: log}, noIdP{}, time.Hour)
	h, err := build(Params{
		Admin:    &grpcapi.Admin{Svc: svc, Log: log},
		Internal: &grpcapi.Internal{Svc: svc, Log: log},
		Bundles:  &bundle.Server{Src: svc, Hub: bundle.NewHub(), MaxWait: time.Second, Log: log},
		Pool:     pool,
		Log:      log,
	})
	require.NoError(t, err)
	dial := func(s *grpc.Server) *grpc.ClientConn {
		lis := bufconn.Listen(1 << 20)
		go func() { _ = s.Serve(lis) }()
		t.Cleanup(s.Stop)
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	return stack{h: h, publicGRPC: dial(h.publicGRPC), internalGRPC: dial(h.internalGRPC)}
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
	code, body := do(t, s.h.internalHTTP, "PUT", "/internal/v1/manifests/order", manifest, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, map[string]any{"service": "order", "permissions": float64(2), "routes": float64(2), "changed": true}, body,
		"snake_case JSON, empty fields emitted")

	code, body = do(t, s.h.internalHTTP, "PUT", "/internal/v1/manifests/order", `{"permissions": [{"key": "a:b", "consumers": true}]}`, nil)
	require.Equal(t, http.StatusBadRequest, code, "unknown fields are refused")
	require.Equal(t, "invalid_argument", body["error"])

	code, body = do(t, s.h.internalHTTP, "POST", "/internal/v1/companies", `{"name": "Acme", "admin_sub": "u1"}`, nil)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, true, body["created"])

	code, body = do(t, s.h.internalHTTP, "GET", "/internal/v1/subjects/u1/claims", "", nil)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, body["company_id"], body["company_id"])
	require.Len(t, body["roles"], 1)

	code, body = do(t, s.h.internalHTTP, "GET", "/internal/v1/subjects/nobody/claims", "", nil)
	require.Equal(t, http.StatusNotFound, code)
	require.Equal(t, "not_a_member", body["error"], "the domain reason survives to REST")

	code, _ = do(t, s.h.internalHTTP, "GET", "/healthz", "", nil)
	require.Equal(t, http.StatusOK, code)
	code, _ = do(t, s.h.internalHTTP, "GET", "/bundles/catalogue.tar.gz", "", nil)
	require.Equal(t, http.StatusOK, code)
	code, _ = do(t, s.h.internalHTTP, "GET", "/v1/roles", "", nil)
	require.Equal(t, http.StatusNotFound, code, "the admin API is not on the internal listener")
}

func TestREST_AdminAPI(t *testing.T) {
	s := newStack(t)
	do(t, s.h.internalHTTP, "PUT", "/internal/v1/manifests/order", manifest, nil)
	_, body := do(t, s.h.internalHTTP, "POST", "/internal/v1/companies", `{"name": "Acme", "admin_sub": "u1"}`, nil)
	admin := map[string]string{"X-Bus-Subject": "u1", "X-Bus-Company-Id": body["company_id"].(string), "X-Bus-User-Type": "provider"}

	code, body := do(t, s.h.publicHTTP, "POST", "/v1/roles", `{"name": "Clerk", "permissions": ["order:read"]}`, admin)
	require.Equal(t, http.StatusOK, code, body)
	role := body["role"].(map[string]any)
	require.Equal(t, "Clerk", role["name"])
	require.Equal(t, false, role["grants_all"])

	code, body = do(t, s.h.publicHTTP, "GET", "/v1/roles", "", admin)
	require.Equal(t, http.StatusOK, code)
	require.Len(t, body["roles"], 2)
	var protectedID string
	for _, r := range body["roles"].([]any) {
		if r.(map[string]any)["protected"] == true {
			protectedID = r.(map[string]any)["id"].(string)
		}
	}
	code, body = do(t, s.h.publicHTTP, "PUT", "/v1/roles/"+protectedID, `{"name": "Boss"}`, admin)
	require.Equal(t, http.StatusBadRequest, code)
	require.Equal(t, "protected_role", body["error"])

	consumer := map[string]string{"X-Bus-Subject": "u1", "X-Bus-User-Type": "consumer"}
	code, body = do(t, s.h.publicHTTP, "GET", "/v1/roles", "", consumer)
	require.Equal(t, http.StatusForbidden, code)
	require.Equal(t, "provider_only", body["error"])

	code, _ = do(t, s.h.publicHTTP, "PUT", "/internal/v1/manifests/order", manifest, nil)
	require.Equal(t, http.StatusNotFound, code, "the internal API is not on the public listener")
}

func TestGRPC_BothServices(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	internal := authzv1.NewInternalServiceClient(s.internalGRPC)
	admin := authzv1.NewAdminServiceClient(s.publicGRPC)

	_, err := internal.ApplyManifest(ctx, &authzv1.ApplyManifestRequest{
		Service:     "order",
		Permissions: []*authzv1.ManifestPermission{{Key: "order:read"}},
		Routes:      []*authzv1.ManifestRoute{{Name: "order.read", Permission: "order:read"}},
	})
	require.NoError(t, err)
	co, err := internal.CreateCompany(ctx, &authzv1.CreateCompanyRequest{Name: "Acme", AdminSub: "u1"})
	require.NoError(t, err)

	_, err = internal.GetClaims(ctx, &authzv1.GetClaimsRequest{Sub: "nobody"})
	st := status.Convert(err)
	require.Equal(t, codes.NotFound, st.Code())
	require.Equal(t, "not_a_member", grpcapi.Reason(st))

	md := metadata.Pairs("x-bus-subject", "u1", "x-bus-company-id", co.GetCompanyId(), "x-bus-user-type", "provider")
	roles, err := admin.ListRoles(metadata.NewOutgoingContext(ctx, md), &authzv1.ListRolesRequest{})
	require.NoError(t, err)
	require.Len(t, roles.GetRoles(), 1)
	require.True(t, roles.GetRoles()[0].GetGrantsAll())

	_, err = admin.ListRoles(ctx, &authzv1.ListRolesRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err), "no caller metadata")

	// Two values for one key: trust neither.
	md.Append("x-bus-company-id", "other")
	_, err = admin.ListRoles(metadata.NewOutgoingContext(ctx, md), &authzv1.ListRolesRequest{})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}
