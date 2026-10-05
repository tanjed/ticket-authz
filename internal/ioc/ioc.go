// Package ioc assembles Authz from the packages' fx modules. Each package owns its Module (its
// providers and lifecycle hooks); this only lists them.
//
// The order is the start order: migrations (db), Authz's own manifest (rbac), the bundle
// listener, then the listeners (server). Stop runs in reverse.
package ioc

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/bundle"
	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/internal/logging"
	"github.com/tanjed/bus2/authz/internal/rbac"
	"github.com/tanjed/bus2/authz/internal/rpcapi"
	"github.com/tanjed/bus2/authz/internal/server"
)

// Modules is the whole service.
var Modules = fx.Options(
	logging.Module,
	config.Module,
	db.Module,
	health.Module,
	events.Module,
	idp.Module,
	rbac.Module,
	bundle.Module,
	rpcapi.Module,
	server.Module,
)

// New returns the application.
func New() *fx.App { return fx.New(Modules) }
