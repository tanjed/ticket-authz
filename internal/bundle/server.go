package bundle

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// ContentType tells OPA the server supports long polling; without it OPA falls back to polling.
const ContentType = "application/vnd.openpolicyagent.bundles"

// Source is the data side (rbac.Service).
type Source interface {
	BundleRevisions(ctx context.Context) ([]rbac.BundleRev, error)
	BundleRevision(ctx context.Context, name string) (int64, bool, error)
	BundleSnapshot(ctx context.Context, name string) (rbac.Snapshot, bool, error)
}

var (
	_ Source       = (*rbac.Service)(nil)
	_ http.Handler = (*Server)(nil)
)

// Server answers GET /bundles/{name}.tar.gz, with ETag and long polling (Prefer: wait=N).
type Server struct {
	Src       Source
	Hub       *Hub
	Discovery Discovery
	Policies  []Policy
	Signer    *Signer
	MaxWait   time.Duration
	Log       *slog.Logger

	mu    sync.Mutex
	cache map[string]built
	sf    singleflight.Group
}

type built struct {
	rev      int64
	policies string
	body     []byte
}

// policyKey identifies the policy set a cached tarball was built with.
func policyKey(p []Policy) string { return Revision(rbac.BundleCatalogue, 0, p) }

func (s *Server) etag(name string, rev int64) string {
	return `"` + Revision(name, rev, s.Policies) + `"`
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/bundles/"), ".tar.gz")
	if !ok || name == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	// Subscribe before reading the revision so a change in between is not missed.
	changed, cancel := s.Hub.Subscribe(name)
	defer cancel()

	rev, ok, err := s.Src.BundleRevision(ctx, name)
	if err != nil {
		s.fail(w, name, err)
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	have := r.Header.Get("If-None-Match")
	if wait := s.wait(r); wait > 0 && have == s.etag(name, rev) {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-changed:
			if rev, _, err = s.Src.BundleRevision(ctx, name); err != nil {
				s.fail(w, name, err)
				return
			}
		}
	}
	w.Header().Set("Content-Type", ContentType)
	if have == s.etag(name, rev) {
		w.Header().Set("ETag", s.etag(name, rev))
		w.WriteHeader(http.StatusNotModified)
		return
	}
	b, err := s.get(ctx, name)
	if err != nil {
		s.fail(w, name, err)
		return
	}
	w.Header().Set("ETag", s.etag(name, b.rev))
	_, _ = w.Write(b.body)
}

// wait parses "Prefer: wait=N" (seconds), capped at MaxWait.
func (s *Server) wait(r *http.Request) time.Duration {
	for _, part := range strings.Split(r.Header.Get("Prefer"), ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "wait="); ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return min(time.Duration(n)*time.Second, s.MaxWait)
			}
		}
	}
	return 0
}

// Info is a bundle's name and the revision in its manifest.
type Info struct {
	Name     string
	Revision string
}

// Bundle is a signed bundle, as OPA receives it.
type Bundle struct {
	Info
	Body []byte
}

// List returns every bundle with its manifest revision.
func (s *Server) List(ctx context.Context) ([]Info, error) {
	revs, err := s.Src.BundleRevisions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(revs))
	for _, r := range revs {
		out = append(out, Info{Name: r.Name, Revision: Revision(r.Name, r.Revision, s.Policies)})
	}
	return out, nil
}

// Get returns a bundle at its latest revision; ok is false for an unknown bundle.
func (s *Server) Get(ctx context.Context, name string) (b Bundle, ok bool, err error) {
	c, err := s.get(ctx, name)
	if errors.Is(err, errGone) {
		return Bundle{}, false, nil
	}
	if err != nil {
		return Bundle{}, false, err
	}
	return Bundle{Info: Info{Name: name, Revision: Revision(name, c.rev, s.Policies)}, Body: c.body}, true, nil
}

// get returns the bundle at its latest revision, building it at most once per revision.
func (s *Server) get(ctx context.Context, name string) (built, error) {
	v, err, _ := s.sf.Do(name, func() (any, error) {
		snap, ok, err := s.Src.BundleSnapshot(context.WithoutCancel(ctx), name)
		if err != nil {
			return built{}, err
		}
		if !ok {
			return built{}, errGone
		}
		s.mu.Lock()
		c, hit := s.cache[name]
		s.mu.Unlock()
		// Same revision and same policy (the catalogue ships it): the tarball is identical.
		if hit && c.rev == snap.Revision && c.policies == policyKey(s.Policies) {
			return c, nil
		}
		body, err := Build(name, snap, s.Discovery, s.Policies, s.Signer)
		if err != nil {
			return built{}, err
		}
		c = built{rev: snap.Revision, policies: policyKey(s.Policies), body: body}
		s.mu.Lock()
		if s.cache == nil {
			s.cache = map[string]built{}
		}
		s.cache[name] = c
		s.mu.Unlock()
		return c, nil
	})
	if err != nil {
		return built{}, err
	}
	return v.(built), nil
}

type gone struct{}

func (gone) Error() string { return "bundle disappeared" }

var errGone error = gone{}

func (s *Server) fail(w http.ResponseWriter, name string, err error) {
	s.Log.Error("bundle request failed", "bundle", name, "err", err)
	http.Error(w, "bundle unavailable", http.StatusServiceUnavailable)
}
