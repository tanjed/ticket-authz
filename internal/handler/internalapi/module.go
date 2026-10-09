package internalapi

import "go.uber.org/fx"

// Module serves InternalService and registers it on the internal listener.
var Module = fx.Module("internalapi",
	fx.Provide(New),
	fx.Invoke((*Internal).Register),
)
