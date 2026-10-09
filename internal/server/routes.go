package server

import "github.com/tanjed/bus2/authz/api/gen/bus/authz/v1/authzv1connect"

// wire is every service and route Authz serves, and the listener (trust zone) serving it: the
// one place to add one. A proto service is one line, its generated New...ServiceHandler call
// passed as is; its REST paths come from its google.api.http annotations.
//
// Trust zones: AdminService only public (it trusts the gateway's X-Bus-* headers);
// InternalService only internal.
func wire(p Params) (public, internal *zone) {
	opts := handlerOptions(p.Log)
	public, internal = newZone(), newZone()
	both := zones{public, internal}

	public.Service(authzv1connect.NewAdminServiceHandler(p.Admin, opts...))
	internal.Service(authzv1connect.NewInternalServiceHandler(p.Internal, opts...))
	both.Service(authzv1connect.NewHealthServiceHandler(p.Health, opts...)) // GET /live, /ready
	return public, internal
}
