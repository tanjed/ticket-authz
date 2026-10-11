// Package logging provides the process logger, also used for fx's own events: JSON on stdout, and
// nothing else. The node's agent collects every container's stdout (no code, no setting here).
// A record logged with a context (log.InfoContext, ErrorContext, ...) inside a span carries its
// trace_id and span_id, which link the log line to its trace.
package logging

import (
	"context"
	"log/slog"
	"os"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

var Module = fx.Module("logging",
	fx.Provide(New),
	fx.WithLogger(func(log *slog.Logger) fxevent.Logger { return &fxevent.SlogLogger{Logger: log} }),
)

func New() *slog.Logger {
	log := slog.New(traceIDs{slog.NewJSONHandler(os.Stdout, nil)})
	slog.SetDefault(log)
	return log
}

// traceIDs adds the context's trace_id and span_id to each record.
type traceIDs struct{ slog.Handler }

func (h traceIDs) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(slog.String("trace_id", sc.TraceID().String()), slog.String("span_id", sc.SpanID().String()))
	}
	return h.Handler.Handle(ctx, r)
}

func (h traceIDs) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceIDs{h.Handler.WithAttrs(attrs)}
}

func (h traceIDs) WithGroup(name string) slog.Handler { return traceIDs{h.Handler.WithGroup(name)} }
