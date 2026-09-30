package idp

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module provides the IdP client as Client.
var Module = fx.Module("idp", fx.Provide(
	fx.Annotate(func(cfg config.Config) *HTTP { return New(cfg.IdPInternalURL) }, fx.As(new(Client))),
))
