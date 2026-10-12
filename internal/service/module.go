// Package service lists the services' fx modules. Each service is its own package under
// internal/service (business rules only): it uses repositories (internal/repository/*) through the
// unit of work (internal/db/uow), and shares the escalation rule in service/access.
package service

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/company"
	"github.com/tanjed/bus2/authz/internal/service/resync"
	"github.com/tanjed/bus2/authz/internal/service/role"
	"github.com/tanjed/bus2/authz/internal/service/user"
)

// Module is every service. Order matters for the start hooks: catalogue seeds Authz's own
// manifest, then resync republishes everything to Redis.
var Module = fx.Options(
	catalogue.Module,
	company.Module,
	role.Module,
	user.Module,
	resync.Module,
)
