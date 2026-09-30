package ioc

import (
	"testing"

	"go.uber.org/fx"
)

// The dependency graph is complete and acyclic (nothing is started, nothing connects).
func TestGraph(t *testing.T) {
	if err := fx.ValidateApp(Modules); err != nil {
		t.Fatal(err)
	}
}
