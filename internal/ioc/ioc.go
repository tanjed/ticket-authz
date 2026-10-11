// Package ioc assembles Authz from the packages' fx modules. Each package owns its Module (its
// providers and lifecycle hooks); this only lists them.
//
// The order is the start order: the telemetry providers (telemetry: built first, so they flush
// last on stop), migrations (db), the unit of work (db/uow), repositories (repository), Authz's own manifest
// then the gateway view rebuild (service: catalogue then view), the handler modules declaring
// their services (handler/*), then the router building them and opening the listeners (router,
// last). Stop runs in reverse.
package ioc

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/handler/admin"
	healthhandler "github.com/tanjed/bus2/authz/internal/handler/health"
	"github.com/tanjed/bus2/authz/internal/handler/internalapi"
	"github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/internal/logging"
	"github.com/tanjed/bus2/authz/internal/repository"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service"
	"github.com/tanjed/bus2/authz/internal/telemetry"
)

// Modules is the whole service.
var Modules = fx.Options(
	config.Module,
	telemetry.Module,
	logging.Module,
	db.Module,
	uow.Module,
	health.Module,
	cache.Module,
	events.Module,
	idp.Module,
	repository.Module,
	service.Module,
	healthhandler.Module,
	admin.Module,
	internalapi.Module,
	router.Module,
)

// New returns the application.
func New() *fx.App { return fx.New(Modules) }
