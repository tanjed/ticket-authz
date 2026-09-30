package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	"github.com/tanjed/bus2/authz/internal/bundle"
	"github.com/tanjed/bus2/authz/internal/config"
)

// Params is what the servers need; internal/ioc supplies it.
type Params struct {
	Cfg      config.Config
	Admin    authzv1.AdminServiceServer
	Internal authzv1.InternalServiceServer
	Bundles  *bundle.Server
	Pool     *pgxpool.Pool
	Log      *slog.Logger
}

// listener is one of the four: serve on an open socket, stop gracefully until ctx ends.
type listener struct {
	name  string
	addr  string
	serve func(net.Listener) error
	stop  func(context.Context)
}

// handlers are the four listeners' handlers, built without opening any socket (tests use them).
type handlers struct {
	publicHTTP, internalHTTP http.Handler
	publicGRPC, internalGRPC *grpc.Server
}

func build(p Params) (handlers, error) {
	ctx := context.Background()
	publicGW, internalGW := newGateway(), newGateway()
	// In-process: REST calls the implementations directly, no loopback gRPC hop.
	if err := authzv1.RegisterAdminServiceHandlerServer(ctx, publicGW, p.Admin); err != nil {
		return handlers{}, err
	}
	if err := authzv1.RegisterInternalServiceHandlerServer(ctx, internalGW, p.Internal); err != nil {
		return handlers{}, err
	}
	h := handlers{
		publicHTTP:   publicRouter(publicGW),
		internalHTTP: internalRouter(internalGW, p.Bundles, p.Pool),
		publicGRPC:   newGRPC(p.Log),
		internalGRPC: newGRPC(p.Log),
	}
	authzv1.RegisterAdminServiceServer(h.publicGRPC, p.Admin)
	authzv1.RegisterInternalServiceServer(h.internalGRPC, p.Internal)
	return h, nil
}

// Servers are the four listeners: public REST and gRPC, internal REST and gRPC.
type Servers struct {
	listeners []listener
	log       *slog.Logger
}

func New(p Params) (*Servers, error) {
	h, err := build(p)
	if err != nil {
		return nil, err
	}
	return &Servers{log: p.Log, listeners: []listener{
		httpListener("public-http", p.Cfg.PublicAddr, &http.Server{Handler: h.publicHTTP, ReadHeaderTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second}),
		grpcListener("public-grpc", p.Cfg.PublicGRPCAddr, h.publicGRPC),
		// No WriteTimeout: OPA's bundle long polls hold the response open.
		httpListener("internal-http", p.Cfg.InternalAddr, &http.Server{Handler: h.internalHTTP, ReadHeaderTimeout: 10 * time.Second}),
		grpcListener("internal-grpc", p.Cfg.InternalGRPCAddr, h.internalGRPC),
	}}, nil
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
			if err := l.serve(socks[i]); err != nil {
				s.log.Error("listener failed", "listener", l.name, "err", err)
				onFail(err)
			}
		}()
	}
	return nil
}

// Stop stops all listeners in parallel: open long polls on one must not use up the others' time.
func (s *Servers) Stop(ctx context.Context) {
	var wg sync.WaitGroup
	for _, l := range s.listeners {
		wg.Go(func() { l.stop(ctx) })
	}
	wg.Wait()
}

func httpListener(name, addr string, s *http.Server) listener {
	return listener{name: name, addr: addr,
		serve: func(l net.Listener) error {
			if err := s.Serve(l); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
		stop: func(ctx context.Context) {
			if err := s.Shutdown(ctx); err != nil {
				_ = s.Close() // long polls still open when the stop timeout ends
			}
		},
	}
}

func grpcListener(name, addr string, s *grpc.Server) listener {
	return listener{name: name, addr: addr,
		serve: func(l net.Listener) error {
			if err := s.Serve(l); !errors.Is(err, grpc.ErrServerStopped) {
				return err
			}
			return nil
		},
		stop: func(ctx context.Context) {
			done := make(chan struct{})
			go func() { s.GracefulStop(); close(done) }()
			select {
			case <-done:
			case <-ctx.Done():
				s.Stop()
			}
		},
	}
}
