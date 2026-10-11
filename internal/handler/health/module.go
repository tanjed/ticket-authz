package health

import (
	"log/slog"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	checks "github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/router"
)

// Module serves HealthService on the internal listener (GET /live, /ready: the kubelet probes the
// internal port).
var Module = fx.Module("healthhandler",
	fx.Provide(fx.Private, fx.Annotate(New, fx.As(new(authzv1connect.HealthServiceHandler)))),
	router.Internal(authzv1connect.NewHealthServiceHandler),
)

func New(c checks.Checker, log *slog.Logger) *Handler { return &Handler{Checker: c, Log: log} }
