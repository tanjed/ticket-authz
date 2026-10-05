package rpcapi

import (
	"context"
	"log/slog"
	"strings"

	"connectrpc.com/connect"

	authzv1 "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1"
	authzv1connect "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"
	"github.com/tanjed/bus2/authz/internal/health"
)

// Health implements HealthService: the kubelet's liveness and readiness probes.
type Health struct {
	authzv1connect.UnimplementedHealthServiceHandler
	Checker health.Checker
	Log     *slog.Logger
}

func (s *Health) Live(context.Context, *authzv1.LiveRequest) (*authzv1.LiveResponse, error) {
	return &authzv1.LiveResponse{}, nil
}

func (s *Health) Ready(ctx context.Context, _ *authzv1.ReadyRequest) (*authzv1.ReadyResponse, error) {
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
		return nil, withReason(connect.CodeUnavailable, "unhealthy", "unavailable: "+strings.Join(failed, ", "))
	}
	return &authzv1.ReadyResponse{Components: ok}, nil
}
