package company

import (
	"log/slog"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module provides the Company client as Client.
var Module = fx.Module("company", fx.Provide(
	fx.Annotate(func(cfg config.Config, log *slog.Logger) *Connect { return New(cfg.CompanyInternalURL, log) }, fx.As(new(Client))),
))
