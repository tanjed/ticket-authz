// Package server runs Authz's two listeners: public (company admin API, reachable only from the
// gateway) and internal (seed Jobs, the IdP, OPA bundles). Each serves Connect, gRPC, gRPC-Web
// and REST on one port (HTTP/1.1 and cleartext HTTP/2).
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	"connectrpc.com/vanguard"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/config"
)

// Params is what the servers need; internal/ioc supplies it.
type Params struct {
	Cfg      config.Config
	Admin    authzv1connect.AdminServiceHandler
	Internal authzv1connect.InternalServiceHandler
	Bundles  http.Handler // OPA's bundle endpoint
	Pool     *pgxpool.Pool
	Log      *slog.Logger
}

// handlers are the two listeners' handlers, built without opening any socket (tests use them).
type handlers struct {
	public, internal http.Handler
}

func build(p Params) (handlers, error) {
	opts := handlerOptions(p.Log)
	// Each zone registers only its own service (trust zones: AdminService never on internal,
	// InternalService never on public).
	adminPath, admin := authzv1connect.NewAdminServiceHandler(p.Admin, opts...)
	internalPath, internal := authzv1connect.NewInternalServiceHandler(p.Internal, opts...)
	publicTC, err := newTranscoder(vanguard.NewService(adminPath, admin))
	if err != nil {
		return handlers{}, err
		
	}
	internalTC, err := newTranscoder(vanguard.NewService(internalPath, internal))
	if err != nil {
		return handlers{}, err
	}
	return handlers{
		public:   publicRouter(zone{rpcPath: adminPath, restPrefix: "/v1/", transcoder: publicTC, extras: extras(authzv1connect.AdminServiceName)}),
		internal: internalRouter(zone{rpcPath: internalPath, restPrefix: "/internal/", transcoder: internalTC, extras: extras(authzv1connect.InternalServiceName)}, p.Bundles, p.Pool),
	}, nil
}

// extras: the standard health service (the kubelet's liveness probe) and reflection (grpcurl,
// buf curl), each listing only the zone's own service.
func extras(service string) map[string]http.Handler {
	out := map[string]http.Handler{}
	add := func(path string, h http.Handler) { out[path] = h }
	add(grpchealth.NewHandler(grpchealth.NewStaticChecker(service)))
	reflector := grpcreflect.NewStaticReflector(service)
	add(grpcreflect.NewHandlerV1(reflector))
	add(grpcreflect.NewHandlerV1Alpha(reflector))
	return out
}

// Servers are the two listeners.
type Servers struct {
	listeners []listener
	log       *slog.Logger
}

// listener is one listener: its server, and the address it opens.
type listener struct {
	name string
	addr string
	srv  *http.Server
}

func New(p Params) (*Servers, error) {
	h, err := build(p)
	if err != nil {
		return nil, err
	}
	return &Servers{log: p.Log, listeners: []listener{
		{"public", p.Cfg.PublicAddr, newHTTPServer(h.public, 30*time.Second)},
		// No WriteTimeout: OPA's bundle long polls hold the response open.
		{"internal", p.Cfg.InternalAddr, newHTTPServer(h.internal, 0)},
	}}, nil
}

// newHTTPServer speaks HTTP/1.1 and cleartext HTTP/2 (h2c): gRPC needs HTTP/2, and TLS ends
// before Authz (the gateway, the mesh).
func newHTTPServer(h http.Handler, writeTimeout time.Duration) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Server{Handler: h, Protocols: protocols, ReadHeaderTimeout: 10 * time.Second, WriteTimeout: writeTimeout}
}

// Start opens every socket first, so a taken port fails the start rather than a later crash,
// then serves each in the background. onFail is called if a listener stops unexpectedly.
func (s *Servers) Start(onFail func(error)) error {
	socks := make([]net.Listener, 0, len(s.listeners))
	for _, l := range s.listeners {
		sock, err := net.Listen("tcp", l.addr)
		if err != nil {
			for _, open := range socks {
				_ = open.Close()
			}
			return err
		}
		socks = append(socks, sock)
	}
	for i, l := range s.listeners {
		go func() {
			s.log.Info("listening", "listener", l.name, "addr", l.addr)
			if err := l.srv.Serve(socks[i]); !errors.Is(err, http.ErrServerClosed) {
				s.log.Error("listener failed", "listener", l.name, "err", err)
				onFail(err)
			}
		}()
	}
	return nil
}

// Stop stops both listeners in parallel: open long polls on one must not use up the other's time.
func (s *Servers) Stop(ctx context.Context) {
	var wg sync.WaitGroup
	for _, l := range s.listeners {
		wg.Go(func() {
			if err := l.srv.Shutdown(ctx); err != nil {
				_ = l.srv.Close() // long polls still open when the stop timeout ends
			}
		})
	}
	wg.Wait()
}
