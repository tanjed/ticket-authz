package server

import (
	"context"

	"go.uber.org/fx"
)

// Module runs the two listeners; include it last, so they open after everything else started.
var Module = fx.Module("server",
	fx.Provide(New),
	fx.Invoke(runOnStart),
)

func runOnStart(lc fx.Lifecycle, sd fx.Shutdowner, s *Servers) {
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			return s.Start(func(error) { _ = sd.Shutdown(fx.ExitCode(1)) })
		},
		OnStop: func(ctx context.Context) error {
			s.Stop(ctx)
			return nil
		},
	})
}
