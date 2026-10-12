// Package repository lists the repository modules. SQL lives only under internal/repository, one
// package per aggregate; the unit of work is internal/db/uow.
package repository

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/repository/catalogue"
	"github.com/tanjed/bus2/authz/internal/repository/role"
	"github.com/tanjed/bus2/authz/internal/repository/userrole"
)

// Module is every repository.
var Module = fx.Options(
	catalogue.Module,
	role.Module,
	userrole.Module,
)
