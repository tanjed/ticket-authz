package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// A record logged with a span's context carries its trace_id and span_id; one without, neither.
func TestTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(traceIDs{slog.NewJSONHandler(&buf, nil)}).With("svc", "authz")
	ctx, span := sdktrace.NewTracerProvider().Tracer("t").Start(context.Background(), "op")
	defer span.End()

	log.InfoContext(ctx, "in span")
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	sc := trace.SpanContextFromContext(ctx)
	if got["trace_id"] != sc.TraceID().String() || got["span_id"] != sc.SpanID().String() {
		t.Fatalf("ids missing: %v", got)
	}

	buf.Reset()
	log.Info("no span")
	if bytes.Contains(buf.Bytes(), []byte("trace_id")) {
		t.Fatalf("unexpected trace_id: %s", buf.String())
	}
}
