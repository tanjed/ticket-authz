// Package rbac is Authz's domain: the catalogue, companies, roles, members and invitations,
// with their SQL. Every write that changes what the gateway sees updates the gateway view (View,
// Redis) once it has committed (view.go).
package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
)

type Service struct {
	DB        *pgxpool.Pool
	Events    events.Publisher
	IdP       idp.Client
	View      View
	InviteTTL time.Duration
	Now       func() time.Time
}

func New(db *pgxpool.Pool, pub events.Publisher, idpClient idp.Client, view View, inviteTTL time.Duration) *Service {
	return &Service{DB: db, Events: pub, IdP: idpClient, View: view, InviteTTL: inviteTTL, Now: time.Now}
}

// Kind classifies a domain error; the API layer maps it to a gRPC code (and so an HTTP status).
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

func fail(kind Kind, code, msg string, args ...any) error {
	return &Error{Kind: kind, Code: code, Message: fmt.Sprintf(msg, args...)}
}

func notFound(what string) error { return fail(KindNotFound, "not_found", "%s not found", what) }

// AsError returns the domain error inside err, if any.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

func (s *Service) tx(ctx context.Context, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.DB, fn)
}
