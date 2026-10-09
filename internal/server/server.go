// Package server runs Authz's two listeners: public (company admin API, reachable only from the
// gateway) and internal (seed Jobs, the IdP). Each serves Connect, gRPC, gRPC-Web and REST on
// one port (HTTP/1.1 and cleartext HTTP/2).
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/router"
)

// Server is the two listeners, registered as fx lifecycle hooks by Run.
type Server struct {
	lc     fx.Lifecycle
	sd     fx.Shutdowner
	cfg    config.Config
	routes router.Handlers
	log    *slog.Logger
}

// Params is what the server needs; fx fills it.
type Params struct {
	fx.In

	Lifecycle fx.Lifecycle
	Shutdown  fx.Shutdowner
	Config    config.Config
	Routes    router.Handlers
	Log       *slog.Logger
}

func New(p Params) *Server {
	return &Server{lc: p.Lifecycle, sd: p.Shutdown, cfg: p.Config, routes: p.Routes, log: p.Log}
}

// Run adds one lifecycle hook per listener. A taken port fails the start, and fx stops the
// listener already open; a listener that stops unexpectedly shuts the app down.
func (s *Server) Run() error {
	public, internal, err := s.routes.Handlers()
	if err != nil {
		return err
	}
	s.serve("public", s.cfg.PublicAddr, public)
	s.serve("internal", s.cfg.InternalAddr, internal)
	return nil
}

func (s *Server) serve(name, addr string, h http.Handler) {
	srv := newHTTPServer(h, 30*time.Second)
	s.lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			sock, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			s.log.Info("listening", "listener", name, "addr", addr)
			go func() {
				if err := srv.Serve(sock); !errors.Is(err, http.ErrServerClosed) {
					s.log.Error("listener failed", "listener", name, "err", err)
					_ = s.sd.Shutdown(fx.ExitCode(1))
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			if err := srv.Shutdown(ctx); err != nil {
				_ = srv.Close() // requests still open when the stop timeout ends
			}
			return nil
		},
	})
}

// newHTTPServer speaks HTTP/1.1 and cleartext HTTP/2 (h2c): gRPC needs HTTP/2, and TLS ends
// before Authz (the gateway, the mesh).
func newHTTPServer(h http.Handler, writeTimeout time.Duration) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Server{Handler: h, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second, WriteTimeout: writeTimeout}
}
