// Package logging provides the process logger (JSON to stdout), also used for fx's own events.
package logging

import (
	"log/slog"
	"os"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

var Module = fx.Module("logging",
	fx.Provide(func() *slog.Logger {
		log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
		slog.SetDefault(log)
		return log
	}),
	fx.WithLogger(func(log *slog.Logger) fxevent.Logger { return &fxevent.SlogLogger{Logger: log} }),
)
