// Package ioc assembles Authz from the packages' fx modules. Each package owns its Module (its
// providers and lifecycle hooks); this only lists them.
//
// The order is the start order: migrations (db), Authz's own manifest then the gateway view
// rebuild (service), handlers registering with the router (handler/*), then the listeners
// (server). Stop runs in reverse.
package ioc

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/handler/admin"
	healthhandler "github.com/tanjed/bus2/authz/internal/handler/health"
	"github.com/tanjed/bus2/authz/internal/handler/internalapi"
	"github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/internal/logging"
	"github.com/tanjed/bus2/authz/internal/redisview"
	"github.com/tanjed/bus2/authz/internal/repository"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/server"
	"github.com/tanjed/bus2/authz/internal/service"
)

// Modules is the whole service.
var Modules = fx.Options(
	logging.Module,
	config.Module,
	db.Module,
	health.Module,
	redisview.Module,
	events.Module,
	idp.Module,
	repository.Module,
	service.Module,
	router.Module,
	healthhandler.Module,
	admin.Module,
	internalapi.Module,
	server.Module,
)

// New returns the application.
func New() *fx.App { return fx.New(Modules) }
