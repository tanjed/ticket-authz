package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// zone is one trust zone's RPC side: its service under its RPC path (Connect, gRPC, gRPC-Web),
// its REST prefix, and the health and reflection services.
type zone struct {
	rpcPath    string // e.g. /bus.authz.v1.AdminService/
	restPrefix string // e.g. /v1/
	transcoder http.Handler
	extras     map[string]http.Handler // health, reflection: path prefix -> handler
}

func (z zone) mount(r chi.Router) {
	r.Handle(z.rpcPath+"*", z.transcoder)
	r.Handle(z.restPrefix+"*", restErrors(z.transcoder))
	for path, h := range z.extras {
		r.Handle(path+"*", h)
	}
}

// publicRouter: the admin API, under /v1 for REST (APISIX strips its /authz prefix).
func publicRouter(z zone) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	z.mount(r)
	return r
}

// internalRouter: the internal API, OPA's bundles (binary, long-polled: not a proto service) and
// the kubelet's readiness check.
func internalRouter(z zone, bundles http.Handler, pool *pgxpool.Pool) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := pool.Ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/bundles/*", bundles.ServeHTTP)
	z.mount(r)
	return r
}
