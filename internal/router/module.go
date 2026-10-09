package router

import "go.uber.org/fx"

// Module provides the Registry: as Registrar to the modules registering services, as Handlers to
// the server.
var Module = fx.Module("router", fx.Provide(
	fx.Annotate(New, fx.As(new(Registrar)), fx.As(new(Handlers))),
))
