package apperror

import (
	"context"
	"errors"
	"log/slog"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
)

// Errors are formatted here and nowhere else. Services and repositories return application errors
// (transport-neutral, invariant 7), handlers return them untouched, and Interceptor, on every
// service and protocol, turns them into Connect errors. REST bodies are then reshaped by REST.

// ErrorDomain is the ErrorInfo domain; the reason is the application error's code (e.g. "last_admin").
const ErrorDomain = "authz.bus"

var kindCodes = map[Kind]connect.Code{
	KindInvalid:      connect.CodeInvalidArgument,
	KindForbidden:    connect.CodePermissionDenied,
	KindNotFound:     connect.CodeNotFound,
	KindConflict:     connect.CodeAlreadyExists,
	KindPrecondition: connect.CodeFailedPrecondition,
	KindUnavailable:  connect.CodeUnavailable,
}

// Interceptor formats every error a handler returns (toConnect). Add it to every service's
// handler options.
func Interceptor(log *slog.Logger) connect.Interceptor { return errorInterceptor{log: log} }

type errorInterceptor struct{ log *slog.Logger }

var _ connect.Interceptor = errorInterceptor{}

func (i errorInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		res, err := next(ctx, req)
		return res, i.toConnect(req.Spec().Procedure, err)
	}
}

func (i errorInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return i.toConnect(conn.Spec().Procedure, next(ctx, conn))
	}
}

func (errorInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// toConnect: an application error becomes its Connect code with the code as ErrorInfo.reason; a Connect
// error (the framework's own, e.g. a body that does not decode) passes through; anything else
// (Postgres down, a bug) is logged and becomes Internal, without details.
func (i errorInterceptor) toConnect(procedure string, err error) error {
	if err == nil {
		return nil
	}
	if e, ok := As(err); ok {
		return withReason(kindCodes[e.Kind], e.Code, e.Message)
	}
	if ce := new(connect.Error); errors.As(err, &ce) {
		return err
	}
	i.log.Error("request failed", "procedure", procedure, "err", err)
	return connect.NewError(connect.CodeInternal, errors.New("internal error"))
}

func withReason(code connect.Code, reason, msg string) error {
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
