// Package router holds the services Authz serves and the listener serving each. Modules register
// their own services (fx.Invoke on Registrar); the server gets one handler per listener
// (Handlers).
//
// Public only for services that trust the gateway's X-Bus-* headers (AdminService); Internal for
// seed Jobs and the IdP (InternalService); Both for HealthService. Never register a service on
// the other listener.
package router

import (
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"connectrpc.com/connect"
	"connectrpc.com/vanguard"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Registrar is what a module needs to register its services: pass a generated
// New...ServiceHandler call as is, built with HandlerOptions. Its REST paths come from its
// google.api.http annotations.
type Registrar interface {
	HandlerOptions() []connect.HandlerOption
	Public(path string, h http.Handler)
	Internal(path string, h http.Handler)
	Both(path string, h http.Handler)
}

// Handlers is what the server needs: one handler per listener, built from what was registered.
type Handlers interface {
	Handlers() (public, internal http.Handler, err error)
}

var (
	_ Registrar = (*Registry)(nil)
	_ Handlers  = (*Registry)(nil)
)

// Registry collects each listener's services. Registering after Handlers is a bug (the service
// would never be served), so it panics.
type Registry struct {
	log              *slog.Logger
	mu               sync.Mutex
	built            bool
	public, internal []entry
}

type entry struct {
	path    string // e.g. /bus.authz.v1.AdminService/
	handler http.Handler
}

func New(log *slog.Logger) *Registry { return &Registry{log: log} }

// HandlerOptions: Authz's JSON codec, and panics become Internal (logged) on every protocol.
func (r *Registry) HandlerOptions() []connect.HandlerOption { return handlerOptions(r.log) }

func (r *Registry) Public(path string, h http.Handler)   { r.add(path, h, &r.public) }
func (r *Registry) Internal(path string, h http.Handler) { r.add(path, h, &r.internal) }
func (r *Registry) Both(path string, h http.Handler)     { r.add(path, h, &r.public, &r.internal) }

func (r *Registry) add(path string, h http.Handler, to ...*[]entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.built {
		panic(fmt.Sprintf("router: %s registered after the handlers were built", path))
	}
	for _, list := range to {
		*list = append(*list, entry{path, h})
	}
}

func (r *Registry) Handlers() (public, internal http.Handler, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.built = true
	if public, err = handler(r.public); err != nil {
		return nil, nil, err
	}
	if internal, err = handler(r.internal); err != nil {
		return nil, nil, err
	}
	return public, internal, nil
}

// handler builds one listener's handler. Each service's RPC path goes to its transcoder as it
// is (Connect, gRPC, gRPC-Web keep their own errors); every other path is REST (the transcoder
// matches the google.api.http annotations, unknown paths are 404) behind restErrors.
func handler(services []entry) (http.Handler, error) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	if len(services) == 0 {
		return r, nil
	}

	vs := make([]*vanguard.Service, 0, len(services))
	for _, s := range services {
		vs = append(vs, vanguard.NewService(s.path, s.handler))
	}
	tc, err := vanguard.NewTranscoder(vs)
	if err != nil {
		return nil, err
	}
	for _, s := range services {
		r.Handle(s.path+"*", tc)
	}
	r.Handle("/*", restErrors(tc))
	return r, nil
}
