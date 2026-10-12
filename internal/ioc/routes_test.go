package ioc

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/handler/admin"
	healthhandler "github.com/tanjed/bus2/authz/internal/handler/health"
	"github.com/tanjed/bus2/authz/internal/handler/internalapi"
	"github.com/tanjed/bus2/authz/internal/health"
	"github.com/tanjed/bus2/authz/internal/router"
	"github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/company"
	"github.com/tanjed/bus2/authz/internal/service/role"
	"github.com/tanjed/bus2/authz/internal/service/user"
)

// The handler modules declare their services into the router's group, each on its own listener:
// AdminService public only, InternalService internal only, HealthService internal only.
func TestRoutes_ModulesDeclareServices(t *testing.T) {
	var routes *router.Router
	app := fx.New(fx.NopLogger,
		healthhandler.Module, admin.Module, internalapi.Module, router.Module,
		fx.Supply(slog.New(slog.NewTextHandler(io.Discard, nil)), config.Config{}),
		fx.Supply(&catalogue.Service{}, &company.Service{}, &role.Service{}, &user.Service{}),
		fx.Provide(func() health.Checker { return health.New(nil) }),
		fx.Populate(&routes),
	)
	if err := app.Err(); err != nil {
		t.Fatal(err)
	}
	public, internal := routes.Handlers()
	// Connect JSON calls that fail before reaching a service (no caller headers, a bad status);
	// GET /live is REST. Anything but 404 means the listener serves the path.
	served := func(h http.Handler, path string) bool {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if path != "/live" {
			req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Connect-Protocol-Version", "1")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code != http.StatusNotFound
	}
	for _, c := range []struct {
		path             string
		public, internal bool
	}{
		{"/live", false, true},
		{"/bus.authz.v1.AdminService/ListRoles", true, false},
		{"/bus.authz.v1.InternalService/SetCompanyStatus", false, true},
		{"/bus.authz.v1.InternalService/CreateAdminRole", false, true},
		{"/bus.authz.v1.InternalService/RevokeUser", false, true},
		{"/bus.authz.v1.AdminService/ListUserRoles", true, false},
	} {
		if got := served(public, c.path); got != c.public {
			t.Errorf("public %s served = %v, want %v", c.path, got, c.public)
		}
		if got := served(internal, c.path); got != c.internal {
			t.Errorf("internal %s served = %v, want %v", c.path, got, c.internal)
		}
	}
}
