package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// publicRouter: the admin API's REST gateway, under /v1 (APISIX strips its /authz prefix).
func publicRouter(gw http.Handler) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.Recoverer)
	r.Handle("/v1/*", gw)
	return r
}

// internalRouter: the internal REST gateway, OPA's bundles (binary, long-polled: not a proto
// service) and the kubelet's health check.
func internalRouter(gw, bundles http.Handler, pool *pgxpool.Pool) http.Handler {
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
	r.Handle("/internal/*", gw)
	return r
}
