package idp

import (
	"net/http"
	"time"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module provides the IdP client as Client.
var Module = fx.Module("idp", fx.Provide(
	fx.Annotate(func(cfg config.Config) *HTTP { return New(cfg.IdPInternalURL) }, fx.As(new(Client))),
))

func New(baseURL string) *HTTP {
	return &HTTP{BaseURL: baseURL, HTTP: &http.Client{Timeout: 5 * time.Second}}
}
