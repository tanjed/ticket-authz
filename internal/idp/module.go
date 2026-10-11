package idp

import (
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module provides the IdP client as Client.
var Module = fx.Module("idp", fx.Provide(
	fx.Annotate(func(cfg config.Config) *HTTP { return New(cfg.IdPInternalURL) }, fx.As(new(Client))),
))

// New: each call is a client span and carries the traceparent (otelhttp).
func New(baseURL string) *HTTP {
	return &HTTP{BaseURL: baseURL, HTTP: &http.Client{Timeout: 5 * time.Second, Transport: otelhttp.NewTransport(http.DefaultTransport)}}
}
