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
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/catalogue"
	"github.com/tanjed/bus2/authz/internal/config"
	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
	"github.com/tanjed/bus2/authz/internal/repository"
	"github.com/tanjed/bus2/authz/internal/service"
	"github.com/tanjed/bus2/authz/internal/service/access"
	catalogsvc "github.com/tanjed/bus2/authz/internal/service/catalogue"
	"github.com/tanjed/bus2/authz/internal/service/company"
	"github.com/tanjed/bus2/authz/internal/service/invitation"
	"github.com/tanjed/bus2/authz/internal/service/member"
	"github.com/tanjed/bus2/authz/internal/service/resync"
	"github.com/tanjed/bus2/authz/internal/service/role"
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

type fakeIdP struct {
	byPhone map[string]string
	sent    []idp.Invitation
	sendErr error
}

func (f *fakeIdP) IdentityByPhone(_ context.Context, phone string) (string, error) {
	return f.byPhone[phone], nil
}

func (f *fakeIdP) SendInvitation(_ context.Context, inv idp.Invitation) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, inv)
	return nil
}

var (
	_ events.Publisher = (*fakeEvents)(nil)
	_ idp.Client       = (*fakeIdP)(nil)
)

type env struct {
	catalogue   *catalogsvc.Service
	companies   *company.Service
	roles       *role.Service
	members     *member.Service
	invitations *invitation.Service
	resync      *resync.Service
	ev          *fakeEvents
	idp         *fakeIdP
	rdb         *redis.Client // what Authz published, read back as the gateway would
	ctx         context.Context
}

// newService resets the database. Tests in this package do not run in parallel.
func newService(t *testing.T) env {
	t.Helper()
	ctx := context.Background()
	testdb.Reset(t, pool)
	ev, fi := &fakeEvents{}, &fakeIdP{byPhone: map[string]string{}}
	rdb := redis.NewClient(&redis.Options{Addr: miniredis.RunT(t).Addr()})
	e := env{ev: ev, idp: fi, rdb: rdb, ctx: ctx}
	// The real modules, not started: their boot hooks (seed, rebuild) do not run.
	app := fx.New(fx.NopLogger,
		uow.Module, repository.Module, service.Module,
		fx.Supply(db.WritePool{Pool: pool}, db.ReadPool{Pool: testdb.ReadOnly(t, pool)}, slog.New(slog.NewTextHandler(io.Discard, nil)), config.Config{InviteTTL: 7 * 24 * time.Hour}),
		fx.Provide(
			func() cache.Publisher {
				return &cache.Redis{C: rdb, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			},
			func() events.Publisher { return ev },
			func() idp.Client { return fi },
		),
		fx.Populate(&e.catalogue, &e.companies, &e.roles, &e.members, &e.invitations, &e.resync),
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

// company creates a company with admin sub "admin-<name>" and returns its id and admin caller.
func (e env) company(t *testing.T, name string) (string, access.Caller) {
	t.Helper()
	id, created, err := e.companies.Create(e.ctx, name, "admin-"+name)
	require.NoError(t, err)
	require.True(t, created)
	return id, access.Caller{Sub: "admin-" + name, CompanyID: id}
}

// hash reads a published HASH (empty when the key is absent).
func (e env) hash(t *testing.T, key string) map[string]string {
	t.Helper()
	h, err := e.rdb.HGetAll(e.ctx, key).Result()
	require.NoError(t, err)
	return h
}

// version reads a member's authorization version as published; 0 when absent.
func (e env) version(t *testing.T, sub string) int64 {
	t.Helper()
	v, err := e.rdb.Get(e.ctx, cache.UserVersionKey(sub)).Int64()
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
