package router_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/db"
	healthhandler "github.com/tanjed/bus2/authz/internal/handler/health"
	"github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/telemetry/telemetrytest"
)

// One REST call is one server span continuing the caller's trace (the gateway's traceparent), and
// the query it runs is a child span of it.
func TestTelemetry_RPCSpanWithDatabaseChild(t *testing.T) {
	ctx := context.Background()
	rec := telemetrytest.Record(t)
	traced, err := db.Open(ctx, pool.Config().ConnString())
	require.NoError(t, err)
	t.Cleanup(traced.Close)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	opts, err := router.NewHandlerOptions(log)
	require.NoError(t, err)
	probe := health.Probe{Name: "db", Check: func(ctx context.Context) error {
		_, err := traced.Exec(ctx, "SELECT 1")
		return err
	}}
	r, err := router.New(router.Params{Log: log, Services: []router.Service{
		router.Mount(router.InternalListener, authzv1connect.NewHealthServiceHandler,
			authzv1connect.HealthServiceHandler(healthhandler.New(health.New([]health.Probe{probe}), log)), opts),
	}})
	require.NoError(t, err)
	_, internal := r.Handlers()

	// The gateway's span.
	gateway, span := sdktrace.NewTracerProvider().Tracer("gateway").Start(ctx, "gateway")
	span.End()
	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	propagation.TraceContext{}.Inject(gateway, propagation.HeaderCarrier(req.Header))
	res := httptest.NewRecorder()
	internal.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())

	var rpc, query sdktrace.ReadOnlySpan
	for _, s := range rec.Ended() {
		switch {
		case s.SpanKind() == trace.SpanKindServer:
			rpc = s
		case strings.Contains(s.Name(), "SELECT"):
			query = s
		}
	}
	require.NotNil(t, rpc, "server span")
	require.Equal(t, "bus.authz.v1.HealthService/Ready", rpc.Name())
	require.Equal(t, trace.SpanContextFromContext(gateway).TraceID(), rpc.SpanContext().TraceID(), "continues the gateway's trace")
	require.NotNil(t, query, "query span")
	require.Equal(t, rpc.SpanContext().SpanID(), query.Parent().SpanID(), "the query is a child of the RPC")
}
