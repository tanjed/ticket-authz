// Package grpcapi implements the proto services (AdminService, InternalService) over rbac. The
// same implementations serve gRPC and, through grpc-gateway registered in-process, REST.
package grpcapi

import (
	"log/slog"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// ErrorDomain is the ErrorInfo domain; the reason is the domain error's code (e.g. "last_admin").
const ErrorDomain = "authz.bus"

var kindCodes = map[rbac.Kind]codes.Code{
	rbac.KindInvalid:      codes.InvalidArgument,
	rbac.KindForbidden:    codes.PermissionDenied,
	rbac.KindNotFound:     codes.NotFound,
	rbac.KindConflict:     codes.AlreadyExists,
	rbac.KindPrecondition: codes.FailedPrecondition,
	rbac.KindUnavailable:  codes.Unavailable,
}

// toStatus turns a domain error into a status carrying its reason; anything else (Postgres down,
// a bug) becomes Internal without details, and is logged.
func toStatus(log *slog.Logger, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	e, ok := rbac.AsError(err)
	if !ok {
		log.Error("request failed", "err", err)
		return status.Error(codes.Internal, "internal error")
	}
	return withReason(kindCodes[e.Kind], e.Code, e.Message)
}

func withReason(code codes.Code, reason, msg string) error {
	st := status.New(code, msg)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: ErrorDomain}); err == nil {
		return d.Err()
	}
	return st.Err()
}

// Reason extracts the ErrorInfo reason from a status, or "" if it has none.
func Reason(st *status.Status) string {
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	return ""
}
