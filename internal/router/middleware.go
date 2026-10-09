package router

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"connectrpc.com/connect"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

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
