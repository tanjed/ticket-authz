// Package health checks the dependencies Authz needs to serve. Each package that owns a
// dependency contributes a Probe to the ProbeGroup; the Checker runs them all.
package health

import (
	"context"
	"time"
)

// ProbeGroup is the fx value group the probes are provided into.
const ProbeGroup = `group:"health_probes"`

// timeout bounds one whole check: a hung dependency is a failed one.
const timeout = 2 * time.Second

// Probe checks one dependency; nil means healthy.
type Probe struct {
	Name  string
	Check func(context.Context) error
}

// Component is one probe's result.
type Component struct {
	Name string
	Err  error
}

// Checker runs every probe.
type Checker interface {
	Check(ctx context.Context) []Component
}

var _ Checker = (*Probes)(nil)

// Probes is the Checker over a fixed set of probes, run in order.
type Probes struct {
	list []Probe
}

func New(probes []Probe) *Probes { return &Probes{list: probes} }

func (p *Probes) Check(ctx context.Context) []Component {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := make([]Component, 0, len(p.list))
	for _, pr := range p.list {
		out = append(out, Component{Name: pr.Name, Err: pr.Check(ctx)})
	}
	return out
}
