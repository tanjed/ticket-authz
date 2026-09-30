// Package bundle serves OPA bundles: it builds tarballs from rbac snapshots, caches them per
// revision, and holds long polls until a revision changes.
package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// Discovery is what the discovery bundle tells OPA about the other bundles.
type Discovery struct {
	Service         string // the service name in OPA's boot config
	LongPollSeconds int
}

// Policy is the rego source shipped in the catalogue bundle.
type Policy struct {
	Path   string // path inside the bundle, under the bus/authz root
	Source []byte
}

// OPAName is the bundle's name in OPA's config; resource paths keep the "/".
func OPAName(name string) string {
	if id, ok := strings.CutPrefix(name, "companies/"); ok {
		return "company-" + id
	}
	return name
}

// Revision is the bundle's .manifest revision and ETag. The catalogue carries the policy, which
// changes with a deploy rather than with a database write, so its hash is part of the revision:
// OPAs holding the old policy see a new revision and download it.
func Revision(name string, rev int64, policies []Policy) string {
	r := strconv.FormatInt(rev, 10)
	if name != rbac.BundleCatalogue {
		return r
	}
	h := sha256.New()
	for _, p := range policies {
		h.Write([]byte(p.Path))
		h.Write([]byte{0})
		h.Write(p.Source)
		h.Write([]byte{0})
	}
	return r + "-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// Build renders one bundle as a gzipped tarball.
func Build(name string, snap rbac.Snapshot, d Discovery, policies []Policy) ([]byte, error) {
	files := map[string]any{}
	var roots []string
	switch {
	case name == rbac.BundleDiscovery:
		bundles := map[string]any{}
		add := func(n string) {
			bundles[OPAName(n)] = map[string]any{
				"service":  d.Service,
				"resource": "bundles/" + n + ".tar.gz",
				"polling":  map[string]any{"long_polling_timeout_seconds": d.LongPollSeconds},
			}
		}
		add(rbac.BundleCatalogue)
		add(rbac.BundleConsumer)
		for _, id := range snap.CompanyIDs {
			add(rbac.CompanyBundle(id))
		}
		files["bus/config/data.json"] = map[string]any{"bundles": bundles}
	case name == rbac.BundleCatalogue:
		roots = []string{"catalogue", "bus/authz"}
		files["catalogue/data.json"] = map[string]any{"routes": orEmpty(snap.Routes)}
	case name == rbac.BundleConsumer:
		roots = []string{"consumer"}
		files["consumer/data.json"] = map[string]any{"permissions": orEmpty(snap.Consumer)}
	case strings.HasPrefix(name, "companies/") && snap.Company != nil:
		roots = []string{name}
		files[name+"/data.json"] = snap.Company
	default:
		return nil, fmt.Errorf("unknown bundle %q", name)
	}
	manifest := map[string]any{"revision": Revision(name, snap.Revision, policies)}
	if roots != nil {
		manifest["roots"] = roots
	}
	files[".manifest"] = manifest

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(path string, body []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: "/" + path, Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		_, err := tw.Write(body)
		return err
	}
	for path, v := range files {
		body, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		if err := write(path, body); err != nil {
			return nil, err
		}
	}
	if name == rbac.BundleCatalogue {
		for _, p := range policies {
			if err := write("bus/authz/"+p.Path, p.Source); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// orEmpty keeps an empty set as {} rather than null, so the policy can index it.
func orEmpty[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}
