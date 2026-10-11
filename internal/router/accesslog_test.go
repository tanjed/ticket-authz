package router

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/telemetry/telemetrytest"
)

// claims answers GetClaims by subject: "ok", "missing" (an application error), anything else a
// raw error.
type claims struct {
	authzv1connect.UnimplementedInternalServiceHandler
}

func (claims) GetClaims(_ context.Context, req *authzv1.GetClaimsRequest) (*authzv1.GetClaimsResponse, error) {
	switch req.GetSub() {
	case "ok":
		return &authzv1.GetClaimsResponse{}, nil
	case "missing":
		return nil, apperror.Fail(apperror.KindNotFound, "subject_not_found", "no such subject")
	}
	return nil, errors.New("postgres down")
}

// One line per request with what the caller sent and got, and, when it reached a service, the
// call's procedure, code and trace; at the level of whose fault it is; none for health probes.
func TestAccessLog(t *testing.T) {
	telemetrytest.Record(t)
	logs := &capture{}
	log := slog.New(logs)
	opts, err := NewHandlerOptions(log)
	require.NoError(t, err)
	r, err := New(Params{Log: log, Services: []Service{
		Mount(InternalListener, authzv1connect.NewInternalServiceHandler, authzv1connect.InternalServiceHandler(claims{}), opts),
		Mount(InternalListener, authzv1connect.NewHealthServiceHandler, authzv1connect.HealthServiceHandler(authzv1connect.UnimplementedHealthServiceHandler{}), opts),
	}})
	require.NoError(t, err)
	_, h := r.Handlers()

	serve := func(method, path, body string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Connect-Protocol-Version", "1")
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	serve(http.MethodPost, "/bus.authz.v1.InternalService/GetClaims", `{"sub":"ok"}`)
	serve(http.MethodGet, "/internal/v1/subjects/missing/claims", "")
	serve(http.MethodGet, "/internal/v1/subjects/broken/claims", "")
	serve(http.MethodGet, "/nowhere", "")
	serve(http.MethodGet, "/ready", "")

	lines := logs.lines("http")
	for _, want := range []struct {
		path, protocol, status, code, reason string
		level                                slog.Level
		inSpan                               bool
	}{
		{"/bus.authz.v1.InternalService/GetClaims", "connect", "200", "ok", "", slog.LevelInfo, true},
		{"/internal/v1/subjects/missing/claims", "rest", "404", "not_found", "subject_not_found", slog.LevelWarn, true},
		{"/internal/v1/subjects/broken/claims", "rest", "500", "internal", "", slog.LevelError, true},
		{"/nowhere", "rest", "404", "", "", slog.LevelWarn, false},
	} {
		l, ok := lines[want.path]
		require.True(t, ok, "%s: no line", want.path)
		require.Equal(t, want.protocol, l.attrs["protocol"], want.path)
		require.Equal(t, want.status, l.attrs["status"], "%s %v", want.path, l.attrs)
		require.Equal(t, want.code, l.attrs["code"], want.path)
		require.Equal(t, want.reason, l.attrs["reason"], want.path)
		require.Equal(t, want.level, l.level, want.path)
		require.Equal(t, want.inSpan, l.inSpan, "%s: carries the call's span", want.path)
		if want.code != "" {
			require.Equal(t, "/bus.authz.v1.InternalService/GetClaims", l.attrs["procedure"], want.path)
		}
	}
	require.Len(t, lines, 4, "none for the health probe")
}

type line struct {
	level  slog.Level
	attrs  map[string]string
	inSpan bool
}

// capture records each line, and whether its context carried a span.
type capture struct {
	mu  sync.Mutex
	got []slog.Record
	ctx []context.Context
}

func (c *capture) Enabled(context.Context, slog.Level) bool { return true }
func (c *capture) WithAttrs([]slog.Attr) slog.Handler       { return c }
func (c *capture) WithGroup(string) slog.Handler            { return c }

func (c *capture) Handle(ctx context.Context, r slog.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got, c.ctx = append(c.got, r), append(c.ctx, ctx)
	return nil
}

// lines are the msg lines by path.
func (c *capture) lines(msg string) map[string]line {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]line{}
	for i, r := range c.got {
		if r.Message != msg {
			continue
		}
		l := line{level: r.Level, attrs: map[string]string{}, inSpan: trace.SpanContextFromContext(c.ctx[i]).IsValid()}
		r.Attrs(func(a slog.Attr) bool { l.attrs[a.Key] = a.Value.String(); return true })
		out[l.attrs["path"]] = l
	}
	return out
}
