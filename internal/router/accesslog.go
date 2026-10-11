package router

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/go-chi/chi/v5/middleware"
	"go.opentelemetry.io/otel/trace"

	"github.com/tanjed/bus2/authz/internal/apperror"
)

// One access log line ("http") per request, written by accessLog around the whole listener
// handler, so it sees what the caller sent and got: method, path, protocol, status, size,
// duration, request id, client address. A request that reaches a service also carries what the
// call recorder (an interceptor, in every service's handler options) left in the request's
// context: the procedure, the Connect code and the application error's reason, and the call's
// span, whose trace_id and span_id the line then carries. A request that never becomes a call
// (an unknown path, a REST body that does not decode) still gets its line, without them.
//
// Info when it succeeds, Warn when the caller is at fault (4xx, or a client error code; gRPC
// always answers 200), Error when the server is. Health probes are not logged: the kubelet calls
// them every few seconds.

// call is what the call recorder fills in for the access log.
type call struct {
	procedure, code, reason string
	span                    trace.SpanContext
}

type callKey struct{}

func accessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Read before serving: the transcoder rewrites a REST request in place (its path becomes
			// the procedure).
			start, method, path, proto := time.Now(), r.Method, r.URL.Path, protocol(r)
			c := &call{}
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r.WithContext(context.WithValue(r.Context(), callKey{}, c)))

			if strings.HasPrefix(c.procedure, "/bus.authz.v1.HealthService/") {
				return
			}
			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			attrs := []slog.Attr{
				slog.String("method", method),
				slog.String("path", path),
				slog.String("protocol", proto),
				slog.Int("status", status),
				slog.Int("bytes", ww.BytesWritten()),
				slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
				slog.String("request_id", middleware.GetReqID(r.Context())),
				slog.String("remote_addr", r.RemoteAddr),
			}
			if c.procedure != "" {
				attrs = append(attrs, slog.String("procedure", c.procedure), slog.String("code", c.code))
			}
			if c.reason != "" {
				attrs = append(attrs, slog.String("reason", c.reason))
			}
			// The call's span, so the log handler adds its trace_id and span_id.
			ctx := trace.ContextWithSpanContext(r.Context(), c.span)
			log.LogAttrs(ctx, level(status, c.code), "http", attrs...)
		})
	}
}

func level(status int, code string) slog.Level {
	if code != "" {
		var c connect.Code
		if code == "ok" {
			return slog.LevelInfo
		}
		if err := c.UnmarshalText([]byte(code)); err == nil && serverFault[c] {
			return slog.LevelError
		}
		return slog.LevelWarn
	}
	switch {
	case status >= 500:
		return slog.LevelError
	case status >= 400:
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// serverFault: the codes that are the server's failure, not the caller's.
var serverFault = map[connect.Code]bool{
	connect.CodeInternal:         true,
	connect.CodeUnknown:          true,
	connect.CodeDataLoss:         true,
	connect.CodeUnavailable:      true,
	connect.CodeDeadlineExceeded: true,
	connect.CodeUnimplemented:    true,
}

// protocol is what the caller speaks: gRPC and gRPC-Web by content type, Connect on a service's
// RPC path (/package.Service/Method), REST otherwise.
func protocol(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "application/grpc-web"):
		return "grpc-web"
	case strings.HasPrefix(ct, "application/grpc"):
		return "grpc"
	case strings.HasPrefix(r.URL.Path, "/bus."):
		return "connect"
	}
	return "rest"
}

// recordCall is the call recorder: it leaves the procedure, the code the caller gets and the
// call's span in the access log's slot. It sits inside the telemetry interceptor (the span) and
// outside the error interceptor (the final code).
func recordCall() connect.Interceptor { return callRecorder{} }

type callRecorder struct{}

var _ connect.Interceptor = callRecorder{}

func (callRecorder) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		record(ctx, req.Spec().Procedure, err)
		return res, err
	}
}

func (callRecorder) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		err := next(ctx, conn)
		record(ctx, conn.Spec().Procedure, err)
		return err
	}
}

func (callRecorder) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func record(ctx context.Context, procedure string, err error) {
	c, ok := ctx.Value(callKey{}).(*call)
	if !ok {
		return
	}
	c.procedure, c.code, c.span = procedure, "ok", trace.SpanContextFromContext(ctx)
	if err != nil {
		c.code, c.reason = connect.CodeOf(err).String(), apperror.Reason(err)
	}
}
