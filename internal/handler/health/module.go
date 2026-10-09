package health

import "go.uber.org/fx"

// Module serves HealthService and registers it on both listeners.
var Module = fx.Module("healthhandler",
	fx.Provide(NewHandler),
	fx.Invoke((*Handler).Register),
)
