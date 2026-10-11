// Package health serves HealthService, the kubelet's liveness and readiness probes, on the
// internal listener.
package health

import (
	"context"
	"log/slog"
	"strings"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/apperror"
	checks "github.com/tanjed/bus2/authz/internal/health"
)

var _ authzv1connect.HealthServiceHandler = (*Handler)(nil)

// Handler implements HealthService: the kubelet's liveness and readiness probes.
type Handler struct {
	authzv1connect.UnimplementedHealthServiceHandler
	Checker checks.Checker
	Log     *slog.Logger
}

func (s *Handler) Live(context.Context, *authzv1.LiveRequest) (*authzv1.LiveResponse, error) {
	return &authzv1.LiveResponse{}, nil
}

func (s *Handler) Ready(ctx context.Context, _ *authzv1.ReadyRequest) (*authzv1.ReadyResponse, error) {
	var ok, failed []string
	for _, c := range s.Checker.Check(ctx) {
		if c.Err != nil {
			s.Log.WarnContext(ctx, "health check failed", "component", c.Name, "err", c.Err)
			failed = append(failed, c.Name)
			continue
		}
		ok = append(ok, c.Name)
	}
	if len(failed) > 0 {
		// Names only: the error details stay in the log.
		return nil, apperror.Fail(apperror.KindUnavailable, "unhealthy", "unavailable: %s", strings.Join(failed, ", "))
	}
	return &authzv1.ReadyResponse{Components: ok}, nil
}
