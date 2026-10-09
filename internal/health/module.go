package health

import "go.uber.org/fx"

// Module provides the Checker over every probe in ProbeGroup, and serves HealthService on both
// listeners.
var Module = fx.Module("health",
	fx.Provide(
		fx.Annotate(New, fx.ParamTags(ProbeGroup), fx.As(new(Checker))),
		NewHandler,
	),
	fx.Invoke((*Handler).Register),
)
