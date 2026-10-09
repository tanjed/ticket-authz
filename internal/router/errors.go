package router

import (
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// ErrorDomain is the ErrorInfo domain; the reason is the domain error's code (e.g. "last_admin").
const ErrorDomain = "authz.bus"

var kindCodes = map[rbac.Kind]connect.Code{
	rbac.KindInvalid:      connect.CodeInvalidArgument,
	rbac.KindForbidden:    connect.CodePermissionDenied,
	rbac.KindNotFound:     connect.CodeNotFound,
	rbac.KindConflict:     connect.CodeAlreadyExists,
	rbac.KindPrecondition: connect.CodeFailedPrecondition,
	rbac.KindUnavailable:  connect.CodeUnavailable,
}

// Error turns a domain error into a Connect error carrying its reason; anything else (Postgres
// down, a bug) becomes Internal without details, and is logged. Handlers return it for every
// error from rbac.
func Error(log *slog.Logger, err error) error {
	if err == nil {
		return nil
	}
	if ce := new(connect.Error); errors.As(err, &ce) {
		return err
	}
	e, ok := rbac.AsError(err)
	if !ok {
		log.Error("request failed", "err", err)
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
	return WithReason(kindCodes[e.Kind], e.Code, e.Message)
}

// WithReason is a Connect error with a stable reason (ErrorInfo), for errors a handler raises
// itself.
func WithReason(code connect.Code, reason, msg string) error {
	ce := connect.NewError(code, errors.New(msg))
	if d, err := connect.NewErrorDetail(&errdetails.ErrorInfo{Reason: reason, Domain: ErrorDomain}); err == nil {
		ce.AddDetail(d)
	}
	return ce
}

// Reason extracts the ErrorInfo reason from an error, or "" if it has none.
func Reason(err error) string {
	ce := new(connect.Error)
	if !errors.As(err, &ce) {
		return ""
	}
	for _, d := range ce.Details() {
		if v, err := d.Value(); err == nil {
			if info, ok := v.(*errdetails.ErrorInfo); ok {
				return info.GetReason()
			}
		}
	}
	return ""
}
