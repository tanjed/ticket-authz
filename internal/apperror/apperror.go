// Package apperror is every error artifact of Authz: the application error (Kind + a stable
// code), the sentinels repositories return, the Postgres mapping, and the one place errors are
// formatted for callers (the Connect interceptor and the REST body). Services and repositories
// stay transport-neutral (invariant 7); only this package knows Connect codes.
package apperror

import (
	"errors"
	"fmt"
)

// Kind classifies an application error; Interceptor maps it to a Connect code.
type Kind int

const (
	KindInvalid      Kind = iota + 1 // bad input
	KindForbidden                    // the caller may not do this
	KindNotFound                     // nothing by that id in the caller's scope
	KindConflict                     // clashes with existing state (taken, already used)
	KindPrecondition                 // not allowed in the current state (protected, last admin, expired)
	KindUnavailable                  // a dependency (the IdP) failed
)

// Error is an application error. Code is the stable machine-readable reason (e.g. "last_admin").
type Error struct {
	Kind    Kind
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// As returns the application error inside err, if any.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// ErrNotFound and ErrDuplicate are what a repository returns for a missing row or a unique
// violation (FromPG), so services can tell them apart without knowing the database.
var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
)

// Fail is an application error.
func Fail(kind Kind, code, msg string, args ...any) error {
	return &Error{Kind: kind, Code: code, Message: fmt.Sprintf(msg, args...)}
}

// NotFound is the error for something missing in the caller's scope.
func NotFound(what string) error { return Fail(KindNotFound, "not_found", "%s not found", what) }

// Escalation is the error for breaking the escalation rule (invariant 5).
func Escalation() error {
	return Fail(KindForbidden, "escalation", "you can only manage roles whose permissions you hold yourself")
}
