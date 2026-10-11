package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"connectrpc.com/vanguard"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/tanjed/bus2/authz/internal/apperror"
)

// JSON uses the proto field names (snake_case), always emits empty fields, and refuses unknown
// ones, so typos in a manifest don't pass silently. REST (Vanguard) and Connect's JSON share it.
var (
	jsonMarshal   = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: true}
	jsonUnmarshal = protojson.UnmarshalOptions{DiscardUnknown: false}
)

// jsonCodec is Connect's "json" codec with the options above.
type jsonCodec struct{}

var _ connect.Codec = jsonCodec{}

func (jsonCodec) Name() string { return "json" }

func (jsonCodec) Marshal(v any) ([]byte, error) {
	m, ok := v.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("json codec: %T is not a proto message", v)
	}
	return jsonMarshal.Marshal(m)
}

func (jsonCodec) Unmarshal(b []byte, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("json codec: %T is not a proto message", v)
	}
	return jsonUnmarshal.Unmarshal(b, m)
}

// HandlerOptions are every service's Connect handler options (router.Module provides them).
type HandlerOptions []connect.HandlerOption

// NewHandlerOptions: the JSON codec; the telemetry interceptor (a server span and the RPC metrics
// per call, on every protocol, REST included; it continues the caller's trace, the gateway's)
// around the error interceptor (the one place errors are formatted), so the span records the
// final code; and panics become Internal (logged).
func NewHandlerOptions(log *slog.Logger) (HandlerOptions, error) {
	tel, err := otelconnect.NewInterceptor(otelconnect.WithTrustRemote())
	if err != nil {
		return nil, err
	}
	return HandlerOptions{
		connect.WithCodec(jsonCodec{}),
		connect.WithInterceptors(tel, apperror.Interceptor(log)),
		connect.WithRecover(func(ctx context.Context, spec connect.Spec, _ http.Header, r any) error {
			log.ErrorContext(ctx, "panic", "procedure", spec.Procedure, "panic", r, "stack", string(debug.Stack()))
			return connect.NewError(connect.CodeInternal, errors.New("internal error"))
		}),
	}, nil
}

// newTranscoder serves Connect handlers as Connect, gRPC, gRPC-Web and, from the proto's
// google.api.http annotations, REST.
func newTranscoder(services ...*vanguard.Service) (http.Handler, error) {
	return vanguard.NewTranscoder(services, vanguard.WithCodec(func(res vanguard.TypeResolver) vanguard.Codec {
		m, u := jsonMarshal, jsonUnmarshal
		m.Resolver, u.Resolver = res, res
		return restJSONCodec{vanguard.JSONCodec{MarshalOptions: m, UnmarshalOptions: u}}
	}))
}

// restJSONCodec is Vanguard's JSON codec, but a body it cannot decode is the caller's mistake
// (InvalidArgument), not Vanguard's default Unknown.
type restJSONCodec struct{ vanguard.JSONCodec }

var (
	_ vanguard.RESTCodec   = restJSONCodec{}
	_ vanguard.StableCodec = restJSONCodec{}
)

func (c restJSONCodec) Unmarshal(b []byte, msg proto.Message) error {
	return invalidArgument(c.JSONCodec.Unmarshal(b, msg))
}

func (c restJSONCodec) UnmarshalField(b []byte, msg proto.Message, f protoreflect.FieldDescriptor) error {
	return invalidArgument(c.JSONCodec.UnmarshalField(b, msg, f))
}

func invalidArgument(err error) error {
	if err == nil {
		return nil
	}
	return connect.NewError(connect.CodeInvalidArgument, err)
}
