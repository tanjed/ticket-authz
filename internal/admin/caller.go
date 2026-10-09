package admin

import (
	"context"

	"connectrpc.com/connect"

	"github.com/tanjed/bus2/authz/internal/rbac"
	"github.com/tanjed/bus2/authz/internal/router"
)

// The caller as the gateway passes it: HTTP headers for REST and Connect, metadata (also HTTP
// headers) for gRPC. Header names are case-insensitive.
const (
	MDSubject  = "X-Bus-Subject"
	MDCompany  = "X-Bus-Company-Id"
	MDUserType = "X-Bus-User-Type"
)

func callerFrom(ctx context.Context) (rbac.Caller, error) {
	info, _ := connect.CallInfoForHandlerContext(ctx)
	get := func(k string) string {
		if info == nil {
			return ""
		}
		if v := info.RequestHeader().Values(k); len(v) == 1 {
			return v[0]
		}
		return "" // absent, or sent twice: trust neither
	}
	if get(MDUserType) != "provider" {
		return rbac.Caller{}, router.WithReason(connect.CodePermissionDenied, "provider_only", "only company users can manage roles")
	}
	return rbac.Caller{Sub: get(MDSubject), CompanyID: get(MDCompany)}, nil
}
