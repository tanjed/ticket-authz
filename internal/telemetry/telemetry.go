// Package telemetry is the in-process half of observability: what only the process can see.
//
//   - Traces (OTEL_TRACES_ENABLED=true): a span per RPC, query, Redis command, Kafka produce, ...
//   - App metrics (OTEL_METRICS_ENABLED=true): RPC durations, Postgres and Redis pools, Kafka
//     client, Go runtime.
//
// Both go over OTLP (gRPC) to the node's agent (OTEL_EXPORTER_OTLP_ENDPOINT). Logs and
// infrastructure metrics are not here: the agent collects them from outside the process (every
// container's stdout, the host, the container runtime), with no code and no setting in the
// service. Logs only need to go to stdout; internal/logging adds the trace_id and span_id that
// link them to a trace.
//
// This is the one place telemetry is set up: Start installs the global tracer and meter
// providers, and every instrumentation reads the globals (otelconnect, otelpgx, redisotel, kotel,
// otelhttp), so nothing else takes a provider. The globals delegate: an instrument created before
// Start reports to the providers Start installs. A signal that is off stays a no-op.
//
// Everything else is the standard OTEL_* environment, read by the SDK itself:
// OTEL_EXPORTER_OTLP_ENDPOINT (default localhost:4317), OTEL_SERVICE_NAME,
// OTEL_RESOURCE_ATTRIBUTES, OTEL_TRACES_SAMPLER, OTEL_METRIC_EXPORT_INTERVAL, ...
package telemetry

import (
	"context"
	"errors"
	"log/slog"

	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Signals says which signals the process exports.
type Signals struct {
	Traces  bool
	Metrics bool
}

// Start installs the W3C trace context and baggage propagators (always: a service that does not
// trace still passes its caller's traceparent on) and, per enabled signal, the global provider
// exporting it over OTLP; name is the default service.name (OTEL_SERVICE_NAME overrides it). The
// returned func flushes and stops them. The exporters connect lazily: an unreachable agent never
// fails the boot (export errors are logged).
func Start(ctx context.Context, name string, on Signals) (shutdown func(context.Context) error, err error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	var stops []func(context.Context) error
	shutdown = func(ctx context.Context) error {
		var errs []error
		for _, stop := range stops {
			errs = append(errs, stop(ctx))
		}
		return errors.Join(errs...)
	}
	if !on.Traces && !on.Metrics {
		return shutdown, nil
	}
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { slog.Warn("otel", "err", err) }))

	// The default name first: OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES (WithFromEnv) win.
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", name)),
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithProcessRuntimeVersion(),
	)
	if err != nil {
		return nil, err
	}

	if on.Traces {
		exp, err := otlptracegrpc.New(ctx)
		if err != nil {
			return nil, err
		}
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exp))
		otel.SetTracerProvider(tp)
		stops = append(stops, tp.Shutdown)
	}
	if on.Metrics {
		exp, err := otlpmetricgrpc.New(ctx)
		if err != nil {
			return nil, err
		}
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res), sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)))
		otel.SetMeterProvider(mp)
		stops = append(stops, mp.Shutdown)
		if err := runtime.Start(); err != nil {
			return nil, err
		}
	}
	return shutdown, nil
}
