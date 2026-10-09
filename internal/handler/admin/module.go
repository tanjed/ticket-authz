package admin

import "go.uber.org/fx"

// Module serves AdminService and registers it on the public listener.
var Module = fx.Module("admin",
	fx.Provide(New),
	fx.Invoke((*Admin).Register),
)
