package config

import (
	"os"

	"go.uber.org/fx"
)

// Module provides Config from the environment.
var Module = fx.Module("config", fx.Provide(func() (Config, error) { return Load(os.Getenv) }))
