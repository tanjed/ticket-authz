package server

import "go.uber.org/fx"

// Module runs the two listeners; include it last, so they open after everything else started
// and every module's fx.Invoke has registered its services with the router.
var Module = fx.Module("server", fx.Provide(New), fx.Invoke((*Server).Run))
