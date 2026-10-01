package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"

	"connectrpc.com/connect"
	"connectrpc.com/vanguard"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
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

// handlerOptions: panics become Internal (logged) on every protocol, REST included.
func handlerOptions(log *slog.Logger) []connect.HandlerOption {
	return []connect.HandlerOption{
		connect.WithCodec(jsonCodec{}),
		connect.WithRecover(func(_ context.Context, spec connect.Spec, _ http.Header, r any) error {
			log.Error("panic", "procedure", spec.Procedure, "panic", r, "stack", string(debug.Stack()))
			return connect.NewError(connect.CodeInternal, errors.New("internal error"))
		}),
	}
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

// restErrors rewrites Vanguard's REST error body (a google.rpc.Status) into the shape REST
// callers read: {"error": <reason>, "message": ...}, with the same HTTP status. The reason is the
// domain code (e.g. "last_admin"), or the RPC code's name. Mount it on REST routes only: Connect
// and gRPC errors keep their own protocol's format.
func restErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &errorCapture{ResponseWriter: w}
		next.ServeHTTP(rw, r)
		if !rw.capturing {
			return
		}
		var st status.Status
		if err := protojson.Unmarshal(rw.body.Bytes(), &st); err != nil {
			w.WriteHeader(rw.code) // not a Status: pass it on untouched
			_, _ = w.Write(rw.body.Bytes())
			return
		}
		reason := ""
		for _, d := range st.GetDetails() {
			info := new(errdetails.ErrorInfo)
			if d.MessageIs(info) && d.UnmarshalTo(info) == nil {
				reason = info.GetReason()
				break
			}
		}
		if reason == "" {
			reason = connect.Code(st.GetCode()).String()
		}
		body, _ := json.Marshal(map[string]string{"error": reason, "message": st.GetMessage()})
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(rw.code)
		_, _ = w.Write(body)
	})
}

// errorCapture holds back a JSON error response so restErrors can rewrite it; anything else is
// written straight through.
type errorCapture struct {
	http.ResponseWriter
	code      int
	capturing bool
	body      bytes.Buffer
}

func (c *errorCapture) WriteHeader(code int) {
	if code >= http.StatusBadRequest && c.Header().Get("Content-Type") == "application/json" {
		c.code, c.capturing = code, true
		c.Header().Del("Content-Length")
		c.Header().Del("Content-Encoding")
		return
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *errorCapture) Write(b []byte) (int, error) {
	if c.capturing {
		return c.body.Write(b)
	}
	return c.ResponseWriter.Write(b)
}

// FlushError holds a captured error back: flushing it through would commit a 200 before
// restErrors writes the real status.
func (c *errorCapture) FlushError() error {
	if c.capturing {
		return nil
	}
	return http.NewResponseController(c.ResponseWriter).Flush()
}

func (c *errorCapture) Unwrap() http.ResponseWriter { return c.ResponseWriter }
