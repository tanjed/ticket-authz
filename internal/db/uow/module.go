package uow

import (
	"log/slog"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/db"
)

// Module provides the unit of work as Transactor (to services) and Querier (to repositories).
var Module = fx.Module("db.uow", fx.Provide(
	fx.Annotate(New, fx.As(new(Transactor)), fx.As(new(Querier))),
))

func New(write db.WritePool, read db.ReadPool, log *slog.Logger) *UnitOfWork {
	return &UnitOfWork{write: write.Pool, read: read.Pool, log: log}
}
