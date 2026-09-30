package idp

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

var Module = fx.Module("idp", fx.Provide(func(cfg config.Config) Client { return New(cfg.IdPInternalURL) }))
