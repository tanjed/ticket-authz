package telemetry

import (
	"context"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module starts the in-process telemetry (Start) as the app's first invoke and flushes it last on
// stop. List it first in ioc.
var Module = fx.Module("telemetry", fx.Invoke(run))

func run(lc fx.Lifecycle, cfg config.Config) error {
	shutdown, err := Start(context.Background(), "authz", Signals{Traces: cfg.OTelTraces, Metrics: cfg.OTelMetrics})
	if err != nil {
		return err
	}
	lc.Append(fx.StopHook(shutdown))
	return nil
}
