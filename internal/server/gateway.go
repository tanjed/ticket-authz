// Package server runs Authz's four listeners: public REST and gRPC (company admin API, reachable
// only from the gateway) and internal REST and gRPC (seed Jobs, the IdP, OPA bundles).
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/tanjed/bus2/authz/internal/grpcapi"
)

// newGateway is the REST side of a proto service. JSON uses the proto field names (snake_case),
// always emits empty fields, and refuses unknown ones, so typos in a manifest don't pass silently.
func newGateway() *runtime.ServeMux {
	return runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{
			MarshalOptions:   protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true},
			UnmarshalOptions: protojson.UnmarshalOptions{DiscardUnknown: false},
		}),
		runtime.WithIncomingHeaderMatcher(headerMatcher),
		runtime.WithErrorHandler(errorHandler),
	)
}

// headerMatcher passes the gateway's X-Bus-* headers on as the x-bus-* metadata the admin API
// reads (the same keys a gRPC caller sends).
func headerMatcher(key string) (string, bool) {
	if k := strings.ToLower(key); strings.HasPrefix(k, "x-bus-") {
		return k, true
	}
	return runtime.DefaultHeaderMatcher(key)
}

// errorHandler answers {"error": <reason>, "message": ...} with the status mapped from the gRPC
// code. The reason is the domain code (e.g. "last_admin"), or the gRPC code's name.
func errorHandler(_ context.Context, _ *runtime.ServeMux, _ runtime.Marshaler, w http.ResponseWriter, _ *http.Request, err error) {
	st := status.Convert(err)
	reason := grpcapi.Reason(st)
	if reason == "" {
		reason = strings.ToLower(st.Code().String())
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(runtime.HTTPStatusFromCode(st.Code()))
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason, "message": st.Message()})
}
