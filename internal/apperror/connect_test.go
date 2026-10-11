package apperror

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

func TestErrorInterceptor(t *testing.T) {
	var logs bytes.Buffer
	i := errorInterceptor{log: slog.New(slog.NewTextHandler(&logs, nil))}

	err := i.toConnect("/p", Fail(KindPrecondition, "last_admin", "keep one"))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || Reason(err) != "last_admin" {
		t.Fatalf("domain error: got %v, reason %q", err, Reason(err))
	}

	own := connect.NewError(connect.CodeInvalidArgument, errors.New("bad body"))
	if got := i.toConnect("/p", own); got != own {
		t.Fatalf("a Connect error must pass through, got %v", got)
	}

	err = i.toConnect("/p", errors.New("dial tcp 10.0.0.5:5432: refused"))
	if connect.CodeOf(err) != connect.CodeInternal || strings.Contains(err.Error(), "10.0.0.5") {
		t.Fatalf("an unexpected error must be Internal without details, got %v", err)
	}
	if !strings.Contains(logs.String(), "10.0.0.5") {
		t.Fatal("an unexpected error must be logged")
	}

	if i.toConnect("/p", nil) != nil {
		t.Fatal("nil stays nil")
	}
}
