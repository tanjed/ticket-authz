package repository

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/service"
)

// Module provides the unit of work and every repository's factory: a service builds the
// repositories it needs per call, over the pool or the unit of work's transaction.
var Module = fx.Module("repository", fx.Provide(
	fx.Annotate(NewUnitOfWork, fx.As(new(service.UnitOfWork))),
	func() service.CatalogueRepoFactory { return NewCatalogue },
	func() service.CompanyRepoFactory { return NewCompany },
	func() service.RoleRepoFactory { return NewRole },
	func() service.MemberRepoFactory { return NewMember },
	func() service.InvitationRepoFactory { return NewInvitation },
))
