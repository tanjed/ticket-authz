package catalogue

import (
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/db/uow"
)

// Module provides the catalogue repository as Repo. It runs every query on the unit of work's querier
// for the context: the transaction inside a write, the replica inside a read.
var Module = fx.Module("repository.catalogue", fx.Provide(
	fx.Annotate(New, fx.As(new(Repo))),
))

func New(q uow.Querier) *Repository { return &Repository{db: q} }
