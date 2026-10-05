package health

import "go.uber.org/fx"

// Module provides the Checker over every probe in ProbeGroup.
var Module = fx.Module("health", fx.Provide(
	fx.Annotate(New, fx.ParamTags(ProbeGroup), fx.As(new(Checker))),
))
