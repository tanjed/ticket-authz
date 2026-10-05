package server

import (
	"net/http"
	"strings"

	"connectrpc.com/vanguard"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// zone is one listener's routes: proto services (served together by one Vanguard transcoder)
// and hand-written handlers. wire fills it; router turns it into the listener's handler.
type zone struct {
	services []rpcService
	handlers []rawHandler
}

type rpcService struct {
	path    string // e.g. /bus.authz.v1.AdminService/
	handler http.Handler
}

type rawHandler struct {
	pattern string
	handler http.Handler
}

func newZone() *zone { return &zone{} }

// Service adds a proto service: pass a generated New...ServiceHandler call as is.
func (z *zone) Service(path string, h http.Handler) {
	z.services = append(z.services, rpcService{path, h})
}

// Handle adds a hand-written handler under a chi pattern, optionally method-prefixed
// ("GET /bundles/*").
func (z *zone) Handle(pattern string, h http.Handler) {
	z.handlers = append(z.handlers, rawHandler{pattern, h})
}

// zones adds the same service or handler to several zones.
type zones []*zone

func (zs zones) Service(path string, h http.Handler) {
	for _, z := range zs {
		z.Service(path, h)
	}
}

func (zs zones) Handle(pattern string, h http.Handler) {
	for _, z := range zs {
		z.Handle(pattern, h)
	}
}

// router builds the zone's handler. Each service's RPC path goes to the transcoder as it is
// (Connect, gRPC, gRPC-Web keep their own errors); health and reflection list only the zone's
// services; every other path is REST (the transcoder matches the google.api.http annotations,
// unknown paths are 404) behind restErrors. The hand-written handlers come first in chi's
// matching, being more specific than the REST catch-all.
func (z *zone) router() (http.Handler, error) {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	for _, h := range z.handlers {
		r.Handle(h.pattern, h.handler)
	}
	if len(z.services) == 0 {
		return r, nil
	}

	vs := make([]*vanguard.Service, 0, len(z.services))
	names := make([]string, 0, len(z.services))
	for _, s := range z.services {
		vs = append(vs, vanguard.NewService(s.path, s.handler))
		names = append(names, strings.Trim(s.path, "/"))
	}
	tc, err := newTranscoder(vs...)
	if err != nil {
		return nil, err
	}
	for _, s := range z.services {
		r.Handle(s.path+"*", tc)
	}
	for path, h := range extras(names...) {
		r.Handle(path+"*", h)
	}
	r.Handle("/*", restErrors(tc))
	return r, nil
}
