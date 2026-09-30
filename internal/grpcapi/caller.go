package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// The caller as the gateway passes it: HTTP headers (the REST gateway copies them into incoming
// metadata, see server.headerMatcher) or gRPC metadata.
const (
	MDSubject  = "x-bus-subject"
	MDCompany  = "x-bus-company-id"
	MDUserType = "x-bus-user-type"
)

func callerFrom(ctx context.Context) (rbac.Caller, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	get := func(k string) string {
		if v := md.Get(k); len(v) == 1 {
			return v[0]
		}
		return "" // absent, or sent twice: trust neither
	}
	if get(MDUserType) != "provider" {
		return rbac.Caller{}, withReason(codes.PermissionDenied, "provider_only", "only company users can manage roles")
	}
	return rbac.Caller{Sub: get(MDSubject), CompanyID: get(MDCompany)}, nil
}
