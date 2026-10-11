// Package repository lists the repository modules. SQL lives only under internal/repository, one
// package per aggregate; the unit of work is internal/db/uow.
package repository

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/repository/catalogue"
	"github.com/tanjed/bus2/authz/internal/repository/company"
	"github.com/tanjed/bus2/authz/internal/repository/invitation"
	"github.com/tanjed/bus2/authz/internal/repository/member"
	"github.com/tanjed/bus2/authz/internal/repository/role"
)

// Module is every repository.
var Module = fx.Options(
	catalogue.Module,
	company.Module,
	role.Module,
	member.Module,
	invitation.Module,
)
