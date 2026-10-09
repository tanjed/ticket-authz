// Package health serves HealthService, the kubelet's liveness and readiness probes, on both
// listeners.
package health

import (
	"context"
	"log/slog"
	"strings"

	"connectrpc.com/connect"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	checks "github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/router"
)

var _ authzv1connect.HealthServiceHandler = (*Handler)(nil)

// Handler implements HealthService: the kubelet's liveness and readiness probes.
type Handler struct {
	authzv1connect.UnimplementedHealthServiceHandler
	Checker checks.Checker
	Log     *slog.Logger
}

func NewHandler(c checks.Checker, log *slog.Logger) *Handler { return &Handler{Checker: c, Log: log} }

// Register serves HealthService on both listeners (GET /live, /ready).
func (s *Handler) Register(r router.Registrar) {
	r.Both(authzv1connect.NewHealthServiceHandler(s, r.HandlerOptions()...))
}

func (s *Handler) Live(context.Context, *authzv1.LiveRequest) (*authzv1.LiveResponse, error) {
	return &authzv1.LiveResponse{}, nil
}

func (s *Handler) Ready(ctx context.Context, _ *authzv1.ReadyRequest) (*authzv1.ReadyResponse, error) {
	var ok, failed []string
	for _, c := range s.Checker.Check(ctx) {
		if c.Err != nil {
			s.Log.Warn("health check failed", "component", c.Name, "err", c.Err)
			failed = append(failed, c.Name)
			continue
		}
		ok = append(ok, c.Name)
	}
	if len(failed) > 0 {
		// Names only: the public listener answers this too.
		return nil, router.WithReason(connect.CodeUnavailable, "unhealthy", "unavailable: "+strings.Join(failed, ", "))
	}
	return &authzv1.ReadyResponse{Components: ok}, nil
}
