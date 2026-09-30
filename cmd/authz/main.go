// Command authz is the Bus 2.0 authorization service. On start it applies the database
// migrations, seeds its own manifest, then serves REST and gRPC (public and internal).
package main

import "github.com/tanjed/bus2/authz/internal/ioc"

func main() {
	ioc.New().Run()
}
