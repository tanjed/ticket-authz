package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

func untar(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		require.NoError(t, err)
		body, err := io.ReadAll(tr)
		require.NoError(t, err)
		out[h.Name] = body
	}
}

func jsonOf(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	require.NoError(t, json.Unmarshal(b, &v))
	return v
}

func TestBuild_Catalogue(t *testing.T) {
	b, err := Build(rbac.BundleCatalogue, rbac.Snapshot{Revision: 7, Routes: map[string]rbac.RouteRule{
		"order.create": {Permission: "order:create"}, "health": {Public: true},
	}}, Discovery{}, []Policy{{Path: "authz.rego", Source: []byte("package bus.authz")}})
	require.NoError(t, err)
	files := untar(t, b)
	manifest := jsonOf(t, files["/.manifest"])
	require.Equal(t, []any{"catalogue", "bus/authz"}, manifest["roots"])
	require.Regexp(t, `^7-[0-9a-f]{12}$`, manifest["revision"], "catalogue revision includes the policy hash")
	require.Equal(t, map[string]any{"routes": map[string]any{
		"order.create": map[string]any{"permission": "order:create"},
		"health":       map[string]any{"public": true},
	}}, jsonOf(t, files["/catalogue/data.json"]))
	require.Equal(t, "package bus.authz", string(files["/bus/authz/authz.rego"]))
}

func TestBuild_EmptyConsumerIsAnObject(t *testing.T) {
	b, err := Build(rbac.BundleConsumer, rbac.Snapshot{Revision: 1}, Discovery{}, nil)
	require.NoError(t, err)
	require.Equal(t, `{"permissions":{}}`, string(untar(t, b)["/consumer/data.json"]))
}

func TestBuild_CompanyAndDiscovery(t *testing.T) {
	id := "0b6e3f4e-8a53-4f3e-9d4c-1a2b3c4d5e6f"
	b, err := Build(rbac.CompanyBundle(id), rbac.Snapshot{Revision: 3, Company: &rbac.CompanyRules{
		Status: "active", Roles: map[string]rbac.RoleRule{"r1": {GrantsAll: true, Permissions: map[string]bool{}}},
	}}, Discovery{}, nil)
	require.NoError(t, err)
	files := untar(t, b)
	require.Equal(t, []any{"companies/" + id}, jsonOf(t, files["/.manifest"])["roots"])
	require.Equal(t, "active", jsonOf(t, files["/companies/"+id+"/data.json"])["status"])

	b, err = Build(rbac.BundleDiscovery, rbac.Snapshot{Revision: 2, CompanyIDs: []string{id}}, Discovery{Service: "authz", LongPollSeconds: 30}, nil)
	require.NoError(t, err)
	files = untar(t, b)
	bundles := jsonOf(t, files["/bus/config/data.json"])["bundles"].(map[string]any)
	require.Len(t, bundles, 3)
	require.Equal(t, map[string]any{
		"service": "authz", "resource": "bundles/companies/" + id + ".tar.gz",
		"polling": map[string]any{"long_polling_timeout_seconds": float64(30)},
	}, bundles["company-"+id])
	require.NotContains(t, jsonOf(t, files["/.manifest"]), "roots")
}

// fakeSource is a single catalogue bundle whose revision tests can bump.
type fakeSource struct {
	mu     sync.Mutex
	rev    int64
	builds atomic.Int32
}

func (f *fakeSource) BundleRevision(_ context.Context, name string) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rev, name == rbac.BundleCatalogue, nil
}

func (f *fakeSource) BundleSnapshot(_ context.Context, name string) (rbac.Snapshot, bool, error) {
	f.builds.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	return rbac.Snapshot{Revision: f.rev}, name == rbac.BundleCatalogue, nil
}

func (f *fakeSource) set(rev int64) {
	f.mu.Lock()
	f.rev = rev
	f.mu.Unlock()
}

func newServer(src Source) (*Server, *Hub) {
	h := NewHub()
	return &Server{Src: src, Hub: h, MaxWait: 5 * time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, h
}

func get(s *Server, path string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestServer_ETagAndCache(t *testing.T) {
	src := &fakeSource{rev: 4}
	s, _ := newServer(src)

	rec := get(s, "/bundles/catalogue.tar.gz", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, `"4-`+Revision(rbac.BundleCatalogue, 4, nil)[2:]+`"`, rec.Header().Get("ETag"))
	tag := rec.Header().Get("ETag")
	require.Equal(t, ContentType, rec.Header().Get("Content-Type"))

	rec = get(s, "/bundles/catalogue.tar.gz", map[string]string{"If-None-Match": tag})
	require.Equal(t, http.StatusNotModified, rec.Code)
	first := get(s, "/bundles/catalogue.tar.gz", nil).Body.Bytes()
	require.Equal(t, int32(2), src.builds.Load(), "the snapshot is read for each download")

	// A new policy (a deploy) changes the ETag though the database revision did not move.
	s.Policies = []Policy{{Path: "authz.rego", Source: []byte("package bus.authz # v2")}}
	rec = get(s, "/bundles/catalogue.tar.gz", map[string]string{"If-None-Match": tag})
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEqual(t, first, rec.Body.Bytes(), "not the tarball cached with the old policy")
	s.Policies = nil

	require.Equal(t, http.StatusNotFound, get(s, "/bundles/nope.tar.gz", nil).Code)
	require.Equal(t, http.StatusNotFound, get(s, "/bundles/catalogue", nil).Code)
}

func TestServer_LongPollWakesOnChange(t *testing.T) {
	src := &fakeSource{rev: 1}
	s, hub := newServer(src)

	done := make(chan *httptest.ResponseRecorder)
	go func() {
		done <- get(s, "/bundles/catalogue.tar.gz", map[string]string{"If-None-Match": s.etag(rbac.BundleCatalogue, 1), "Prefer": "wait=5"})
	}()
	select {
	case <-done:
		t.Fatal("long poll returned before any change")
	case <-time.After(200 * time.Millisecond):
	}
	src.set(2)
	hub.Notify(rbac.BundleCatalogue)
	select {
	case rec := <-done:
		require.Equal(t, http.StatusOK, rec.Code)
		require.Equal(t, s.etag(rbac.BundleCatalogue, 2), rec.Header().Get("ETag"))
	case <-time.After(2 * time.Second):
		t.Fatal("long poll was not woken")
	}
}

func TestServer_LongPollTimesOut(t *testing.T) {
	s, _ := newServer(&fakeSource{rev: 1})
	s.MaxWait = 100 * time.Millisecond
	start := time.Now()
	rec := get(s, "/bundles/catalogue.tar.gz", map[string]string{"If-None-Match": s.etag(rbac.BundleCatalogue, 1), "Prefer": "wait=30"})
	require.Equal(t, http.StatusNotModified, rec.Code)
	require.Less(t, time.Since(start), 2*time.Second, "wait is capped at MaxWait")
}

func TestHub_UnsubscribeAndNotifyAll(t *testing.T) {
	h := NewHub()
	a, cancelA := h.Subscribe("x")
	b, cancelB := h.Subscribe("y")
	cancelA()
	h.NotifyAll()
	select {
	case <-b:
	default:
		t.Fatal("NotifyAll did not reach y")
	}
	select {
	case <-a:
		t.Fatal("unsubscribed channel was notified")
	default:
	}
	cancelB()
	require.Empty(t, h.subs)
}
