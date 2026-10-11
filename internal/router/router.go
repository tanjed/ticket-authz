// Package router serves Authz: the two listeners, public (company admin API, reachable only from
// the gateway) and internal (seed Jobs, the IdP, the kubelet), each Connect, gRPC, gRPC-Web and
// REST on one port (HTTP/1.1 and cleartext HTTP/2).
//
// A module declares a service with Public or Internal (its generated New...ServiceHandler, passed
// as is); fx collects them all into the vanguard_services group, and New builds one handler per
// listener from it. REST paths come from the proto's google.api.http annotations.
//
// Public only for services that trust the gateway's X-Bus-* headers (AdminService: the public port
// is reachable from the gateway alone); Internal for everything in-cluster callers use
// (InternalService, and HealthService for the kubelet). Never put a service on the other listener.
package router

import (
	"net/http"

	"connectrpc.com/connect"
	"connectrpc.com/vanguard"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/apperror"
)

// ServicesGroup is the fx value group every Connect service is provided into.
const ServicesGroup = `group:"vanguard_services"`

// Listener is where a service is served.
type Listener int

const (
	PublicListener Listener = iota + 1
	InternalListener
)

// Service is one Connect service and the listener serving it.
type Service struct {
	Listener Listener
	Path     string // e.g. /bus.authz.v1.AdminService/
	Handler  http.Handler
}

// Mounter is a generated New...ServiceHandler: it serves the implementation T at its path.
type Mounter[T any] func(T, ...connect.HandlerOption) (string, http.Handler)

// Public and Internal declare a Connect service from a module: mount is its generated
// New...ServiceHandler, and the implementation T comes from the graph (provide it as T, the
// generated handler interface). The service joins the vanguard_services group.
func Public[T any](mount Mounter[T]) fx.Option   { return provide(PublicListener, mount) }
func Internal[T any](mount Mounter[T]) fx.Option { return provide(InternalListener, mount) }

func provide[T any](l Listener, mount Mounter[T]) fx.Option {
	return fx.Provide(fx.Annotate(func(impl T, opts HandlerOptions) Service {
		return Mount(l, mount, impl, opts)
	}, fx.ResultTags(ServicesGroup)))
}

// Mount builds a Service: mount over impl, with Authz's handler options (NewHandlerOptions).
func Mount[T any](l Listener, mount Mounter[T], impl T, opts HandlerOptions) Service {
	path, h := mount(impl, opts...)
	return Service{Listener: l, Path: path, Handler: h}
}

// handler builds one listener's handler. Each service's RPC path goes to its transcoder as it
// is (Connect, gRPC, gRPC-Web keep their own errors); every other path is REST (the transcoder
// matches the google.api.http annotations, unknown paths are 404) behind apperror.REST.
func handler(services []Service) (http.Handler, error) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	if len(services) == 0 {
		return r, nil
	}

	vs := make([]*vanguard.Service, 0, len(services))
	for _, s := range services {
		vs = append(vs, vanguard.NewService(s.Path, s.Handler))
	}
	tc, err := vanguard.NewTranscoder(vs)
	if err != nil {
		return nil, err
	}
	for _, s := range services {
		r.Handle(s.Path+"*", tc)
	}
	r.Handle("/*", apperror.REST(tc))
	return r, nil
}
