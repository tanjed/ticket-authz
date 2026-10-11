package router

import (
	"fmt"
	"log/slog"
	"net/http"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
)

// Module builds the listeners' handlers from every service in the vanguard_services group and
// runs the listeners. Include it last, so they open after every other start hook (the seed, the
// gateway view rebuild).
var Module = fx.Module("router",
	fx.Provide(New, NewHandlerOptions),
	fx.Invoke((*Router).Run),
)

// Params is what the router needs; fx fills Services from the vanguard_services group.
type Params struct {
	fx.In

	Lifecycle fx.Lifecycle
	Shutdown  fx.Shutdowner
	Config    config.Config
	Log       *slog.Logger
	Services  []Service `group:"vanguard_services"`
}

func New(p Params) (*Router, error) {
	var public, internal []Service
	for _, s := range p.Services {
		switch s.Listener {
		case PublicListener:
			public = append(public, s)
		case InternalListener:
			internal = append(internal, s)
		default:
			return nil, fmt.Errorf("router: %s has no listener", s.Path)
		}
	}
	r := &Router{lc: p.Lifecycle, sd: p.Shutdown, cfg: p.Config, log: p.Log}
	var err error
	if r.public, err = handler(public); err != nil {
		return nil, err
	}
	if r.internal, err = handler(internal); err != nil {
		return nil, err
	}
	return r, nil
}

// Handlers is each listener's handler (tests serve them without opening the configured ports).
func (r *Router) Handlers() (public, internal http.Handler) { return r.public, r.internal }
