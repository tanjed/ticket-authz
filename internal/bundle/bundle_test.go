package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	opabundle "github.com/open-policy-agent/opa/v1/bundle"
	"github.com/stretchr/testify/require"

	"github.com/tanjed/bus2/authz/internal/rbac"
	"github.com/tanjed/bus2/authz/policy"
)

// testKey is one RSA key for the whole package (generating one per test is slow).
var testKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

func testSigner(t *testing.T) (*Signer, string) {
	t.Helper()
	key, err := testKey()
	require.NoError(t, err)
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	s, err := NewSigner(priv, "test")
	require.NoError(t, err)
	return s, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// read loads a bundle the way OPA does, verifying its signature against pub.
func read(t *testing.T, body []byte, pub string) opabundle.Bundle {
	t.Helper()
	b, err := readVerified(body, pub)
	require.NoError(t, err)
	return b
}

func readVerified(body []byte, pub string) (opabundle.Bundle, error) {
	keys := map[string]*opabundle.KeyConfig{"test": {Key: pub, Algorithm: SigningAlg}}
	return opabundle.NewReader(bytes.NewReader(body)).
		WithBundleVerificationConfig(opabundle.NewVerificationConfig(keys, "test", "", nil)).
		Read()
}

func TestBuild_Catalogue(t *testing.T) {
	s, pub := testSigner(t)
	body, err := Build(rbac.BundleCatalogue, rbac.Snapshot{Revision: 7, Routes: map[string]rbac.RouteRule{
		"order.create": {Permission: "order:create"}, "health": {Public: true},
	}}, Discovery{}, []Policy{{Path: "authz.rego", Source: []byte("package bus.authz")}}, s)
	require.NoError(t, err)
	b := read(t, body, pub)
	require.Equal(t, []string{"catalogue", "bus/authz"}, *b.Manifest.Roots)
	require.Regexp(t, `^7-[0-9a-f]{12}$`, b.Manifest.Revision, "catalogue revision includes the policy hash")
	require.Equal(t, map[string]any{"routes": map[string]any{
		"order.create": map[string]any{"permission": "order:create"},
		"health":       map[string]any{"public": true},
	}}, b.Data["catalogue"])
	require.Len(t, b.Modules, 1)
	require.Equal(t, "/bus/authz/authz.rego", b.Modules[0].Path)
	require.Equal(t, "package bus.authz", string(b.Modules[0].Raw), "shipped byte for byte")
}

func TestBuild_EmptyConsumerIsAnObject(t *testing.T) {
	s, pub := testSigner(t)
	body, err := Build(rbac.BundleConsumer, rbac.Snapshot{Revision: 1}, Discovery{}, nil, s)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"permissions": map[string]any{}}, read(t, body, pub).Data["consumer"])
}

func TestBuild_CompanyAndDiscovery(t *testing.T) {
	s, pub := testSigner(t)
	id := "0b6e3f4e-8a53-4f3e-9d4c-1a2b3c4d5e6f"
	body, err := Build(rbac.CompanyBundle(id), rbac.Snapshot{Revision: 3, Company: &rbac.CompanyRules{
		Status: "active", Roles: map[string]rbac.RoleRule{"r1": {GrantsAll: true, Permissions: map[string]bool{}}},
	}}, Discovery{}, nil, s)
	require.NoError(t, err)
	b := read(t, body, pub)
	require.Equal(t, []string{"companies/" + id}, *b.Manifest.Roots)
	require.Equal(t, "active", b.Data["companies"].(map[string]any)[id].(map[string]any)["status"])

	body, err = Build(rbac.BundleDiscovery, rbac.Snapshot{Revision: 2, CompanyIDs: []string{id}}, Discovery{Service: "authz", LongPollSeconds: 30}, nil, s)
	require.NoError(t, err)
	b = read(t, body, pub)
	bundles := b.Data["bus"].(map[string]any)["config"].(map[string]any)["bundles"].(map[string]any)
	require.Len(t, bundles, 3)
	require.Equal(t, map[string]any{
		"service": "authz", "resource": "bundles/companies/" + id + ".tar.gz",
		"polling": map[string]any{"long_polling_timeout_seconds": json.Number("30")},
		"signing": map[string]any{"keyid": "test"},
	}, bundles["company-"+id], "OPA is told to verify every bundle it downloads")
	require.Equal(t, []string{""}, *b.Manifest.Roots, "no roots written: OPA's default, as before")
}

func TestBuild_SignatureIsChecked(t *testing.T) {
	s, pub := testSigner(t)
	body, err := Build(rbac.BundleConsumer, rbac.Snapshot{Revision: 1, Consumer: map[string]bool{"order:read": true}}, Discovery{}, nil, s)
	require.NoError(t, err)

	// Same files, data changed: the signed hashes no longer match.
	tampered := retar(t, body, func(name string, b []byte) []byte {
		if name == "/data.json" {
			return []byte(`{"consumer":{"permissions":{"order:read":true,"order:cancel":true}}}`)
		}
		return b
	})
	_, err = readVerified(tampered, pub)
	require.Error(t, err)

	// Signed by someone else.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	require.NoError(t, err)
	_, err = readVerified(body, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	require.Error(t, err)

	_, err = Build(rbac.BundleConsumer, rbac.Snapshot{Revision: 1}, Discovery{}, nil, nil)
	require.Error(t, err, "no unsigned mode")
}

func TestNewSigner_RejectsBadKeys(t *testing.T) {
	_, err := NewSigner([]byte("not a key"), "k")
	require.Error(t, err)
	_, err = NewSigner([]byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"), "k")
	require.Error(t, err)
	_, err = NewSigner([]byte("-----BEGIN"), "")
	require.Error(t, err)
}

func TestParsePolicies(t *testing.T) {
	require.NoError(t, ParsePolicies([]Policy{{Path: "authz.rego", Source: policy.Rego}}), "the shipped policy parses")
	require.Error(t, ParsePolicies([]Policy{{Path: "bad.rego", Source: []byte("package x\nallow if {")}}))
}

// retar rewrites a bundle's files through f, keeping everything else.
func retar(t *testing.T, body []byte, f func(name string, b []byte) []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(body))
	require.NoError(t, err)
	tr := tar.NewReader(gz)
	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	tw := tar.NewWriter(gw)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		b, err := io.ReadAll(tr)
		require.NoError(t, err)
		b = f(h.Name, b)
		h.Size = int64(len(b))
		require.NoError(t, tw.WriteHeader(h))
		_, err = tw.Write(b)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return out.Bytes()
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

func newServer(t *testing.T, src Source) (*Server, *Hub) {
	h := NewHub()
	signer, _ := testSigner(t)
	return &Server{Src: src, Hub: h, Signer: signer, MaxWait: 5 * time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, h
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
	s, _ := newServer(t, src)

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
	s, hub := newServer(t, src)

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
	s, _ := newServer(t, &fakeSource{rev: 1})
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
