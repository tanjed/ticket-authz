package service

import (
	"errors"
	"fmt"
)

// Kind classifies a domain error; the transport maps it to its own code (router.Error).
type Kind int

const (
	KindInvalid      Kind = iota + 1 // bad input
	KindForbidden                    // the caller may not do this
	KindNotFound                     // nothing by that id in the caller's scope
	KindConflict                     // clashes with existing state (taken, already used)
	KindPrecondition                 // not allowed in the current state (protected, last admin, expired)
	KindUnavailable                  // a dependency (the IdP) failed
)

// Error is a domain error. Code is the stable machine-readable reason (e.g. "last_admin").
type Error struct {
	Kind    Kind
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// AsError returns the domain error inside err, if any.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// Repository errors: what a repository returns for a missing row or a unique violation, so
// services can tell them apart without knowing the database.
var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
)

func fail(kind Kind, code, msg string, args ...any) error {
	return &Error{Kind: kind, Code: code, Message: fmt.Sprintf(msg, args...)}
}

func notFound(what string) error { return fail(KindNotFound, "not_found", "%s not found", what) }

func escalation() error {
	return fail(KindForbidden, "escalation", "you can only manage roles whose permissions you hold yourself")
}

func notAMember() error {
	return fail(KindForbidden, "not_a_member", "caller is not a member of this company")
}
