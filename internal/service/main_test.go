package service_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/company"
	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/repository"
	"github.com/tanjed/bus2/authz/internal/service"
	"github.com/tanjed/bus2/authz/internal/service/access"
	catalogsvc "github.com/tanjed/bus2/authz/internal/service/catalogue"
	companysvc "github.com/tanjed/bus2/authz/internal/service/company"
	"github.com/tanjed/bus2/authz/internal/service/resync"
	"github.com/tanjed/bus2/authz/internal/service/role"
	"github.com/tanjed/bus2/authz/internal/service/user"
	"github.com/tanjed/bus2/authz/internal/testdb"
)

var pool *pgxpool.Pool

// TestMain starts one Postgres for the package; each test resets it (see newService).
func TestMain(m *testing.M) {
	var stop func()
	var err error
	pool, stop, err = testdb.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "postgres:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

type recorded struct {
	Event, CompanyID string
	Data             map[string]any
}

type fakeEvents struct {
	mu   sync.Mutex
	list []recorded
}

func (f *fakeEvents) Publish(_ context.Context, event, companyID string, data map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list = append(f.list, recorded{event, companyID, data})
}

func (f *fakeEvents) names() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.list {
		out = append(out, r.Event)
	}
	return out
}

// fakeCompany is the Company service: who belongs to which company, and each status.
type fakeCompany struct {
	mu       sync.Mutex
	members  map[string]string // user id -> company id
	statuses map[string]string // company id -> status
	down     error
}

func (f *fakeCompany) GetMembership(_ context.Context, userID string) (company.Membership, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return company.Membership{}, f.down
	}
	id, ok := f.members[userID]
	if !ok {
		return company.Membership{}, apperror.ErrNotFound
	}
	return company.Membership{CompanyID: id, Status: f.statuses[id]}, nil
}

func (f *fakeCompany) ListCompanyStatuses(context.Context) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return nil, f.down
	}
	out := map[string]string{}
	for id, st := range f.statuses {
		out[id] = st
	}
	return out, nil
}

var (
	_ events.Publisher = (*fakeEvents)(nil)
	_ company.Client   = (*fakeCompany)(nil)
)

type env struct {
	catalogue *catalogsvc.Service
	companies *companysvc.Service
	roles     *role.Service
	users     *user.Service
	resync    *resync.Service
	ev        *fakeEvents
	co        *fakeCompany
	rdb       *redis.Client // what Authz published, read back as the gateway would
	ctx       context.Context
}

// newService resets the database. Tests in this package do not run in parallel.
func newService(t *testing.T) env {
	t.Helper()
	ctx := context.Background()
	testdb.Reset(t, pool)
	ev, fc := &fakeEvents{}, &fakeCompany{members: map[string]string{}, statuses: map[string]string{}}
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	e := env{ev: ev, co: fc, rdb: rdb, ctx: ctx}
	// The real modules, not started: their boot hooks (seed, rebuild) do not run.
	app := fx.New(fx.NopLogger,
		uow.Module, repository.Module, service.Module,
		fx.Supply(db.WritePool{Pool: pool}, db.ReadPool{Pool: testdb.ReadOnly(t, pool)}, slog.New(slog.NewTextHandler(io.Discard, nil)), config.Config{}),
		fx.Provide(
			func() cache.Publisher {
				return &cache.Redis{C: rdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			},
			func() events.Publisher { return ev },
			func() company.Client { return fc },
		),
		fx.Populate(&e.catalogue, &e.companies, &e.roles, &e.users, &e.resync),
	)
	require.NoError(t, app.Err())
	return e
}

// seed loads a small "order" catalogue.
func (e env) seed(t *testing.T) {
	t.Helper()
	_, err := e.catalogue.ApplyManifest(e.ctx, "order", catalogue.Manifest{
		Permissions: []catalogue.Permission{
			{Key: "order:create", Consumer: true},
			{Key: "order:read", Consumer: true},
			{Key: "order:cancel"},
		},
		Routes: []catalogue.Route{
			{Name: "order.create", Permission: "order:create"},
			{Name: "order.read", Permission: "order:read"},
			{Name: "order.cancel", Permission: "order:cancel"},
			{Name: "order.health", Public: true},
		},
	})
	require.NoError(t, err)
}

// company registers a company in the fake Company service with admin user "admin-<name>", then
// asks Authz for its Admin role as Company does, and returns the id and the admin caller.
func (e env) company(t *testing.T, name string) (string, access.Caller) {
	t.Helper()
	id, admin := uuid.NewString(), "admin-"+name
	e.co.members[admin], e.co.statuses[id] = id, company.StatusActive
	_, err := e.users.CreateAdminRole(e.ctx, id, admin)
	require.NoError(t, err)
	return id, access.Caller{UserID: admin, CompanyID: id}
}

// join makes userID a user of the company in the fake Company service and assigns the roles, as
// Company does when an invitation is accepted.
func (e env) join(t *testing.T, companyID, userID string, roleIDs ...string) {
	t.Helper()
	e.co.members[userID] = companyID
	require.NoError(t, e.users.AssignRoles(e.ctx, companyID, userID, roleIDs))
}

// hash reads a published HASH (empty when the key is absent).
func (e env) hash(t *testing.T, key string) map[string]string {
	t.Helper()
	h, err := e.rdb.HGetAll(e.ctx, key).Result()
	require.NoError(t, err)
	return h
}

// version reads a user's authorization version as published; 0 when absent.
func (e env) version(t *testing.T, userID string) int64 {
	t.Helper()
	v, err := e.rdb.Get(e.ctx, cache.UserVersionKey(userID)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0
	}
	require.NoError(t, err)
	return v
}

func requireStatus(t *testing.T, err error, kind apperror.Kind, code string) {
	t.Helper()
	require.Error(t, err)
	e, ok := apperror.As(err)
	require.True(t, ok, "want domain error, got %v", err)
	require.Equal(t, kind, e.Kind, e.Message)
	if code != "" {
		require.Equal(t, code, e.Code)
	}
}
