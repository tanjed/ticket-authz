// Package bundle serves OPA bundles: it builds signed tarballs from rbac snapshots (with OPA's own
// bundle package), caches them per revision, and holds long polls until a revision changes.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	opabundle "github.com/open-policy-agent/opa/v1/bundle"

	"github.com/tanjed/bus2/authz/internal/rbac"
)

// SigningAlg is the algorithm every bundle is signed with; OPA's keys config must match it.
const SigningAlg = "RS256"

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

// ParsePolicies checks that every policy is valid rego, so a broken policy fails the boot rather
// than every gateway's next bundle activation.
func ParsePolicies(policies []Policy) error {
	for _, p := range policies {
		if _, err := ast.ParseModuleWithOpts(p.Path, string(p.Source), ast.ParserOptions{RegoVersion: ast.RegoV1}); err != nil {
			return fmt.Errorf("policy %s: %w", p.Path, err)
		}
	}
	return nil
}

// Signer signs bundles. OPA verifies every bundle (discovery included) against the public key it
// holds under KeyID, and refuses an unsigned or tampered one.
type Signer struct {
	KeyID  string
	config *opabundle.SigningConfig
}

// NewSigner takes an RSA private key in PEM. It is checked here, so a bad key fails the boot.
func NewSigner(privateKeyPEM []byte, keyID string) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("bundle signing key id is empty")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(privateKeyPEM), []byte("-----BEGIN")) {
		return nil, errors.New("bundle signing key is not PEM")
	}
	c := opabundle.NewSigningConfig(string(privateKeyPEM), SigningAlg, "")
	if _, err := c.GetPrivateKey(); err != nil {
		return nil, fmt.Errorf("bundle signing key: %w", err)
	}
	return &Signer{KeyID: keyID, config: c}, nil
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

// Build renders one bundle as a signed, gzipped tarball.
func Build(name string, snap rbac.Snapshot, d Discovery, policies []Policy, s *Signer) ([]byte, error) {
	if s == nil {
		return nil, errors.New("bundles are always signed: no signer")
	}
	var data any
	var roots []string
	var modules []opabundle.ModuleFile
	switch {
	case name == rbac.BundleDiscovery:
		bundles := map[string]any{}
		add := func(n string) {
			bundles[OPAName(n)] = map[string]any{
				"service":  d.Service,
				"resource": "bundles/" + n + ".tar.gz",
				"polling":  map[string]any{"long_polling_timeout_seconds": d.LongPollSeconds},
				"signing":  map[string]any{"keyid": s.KeyID},
			}
		}
		add(rbac.BundleCatalogue)
		add(rbac.BundleConsumer)
		for _, id := range snap.CompanyIDs {
			add(rbac.CompanyBundle(id))
		}
		data = map[string]any{"bus": map[string]any{"config": map[string]any{"bundles": bundles}}}
	case name == rbac.BundleCatalogue:
		roots = []string{"catalogue", "bus/authz"}
		data = map[string]any{"catalogue": map[string]any{"routes": orEmpty(snap.Routes)}}
		for _, p := range policies {
			path := "/bus/authz/" + p.Path
			modules = append(modules, opabundle.ModuleFile{URL: path, Path: path, Raw: p.Source})
		}
	case name == rbac.BundleConsumer:
		roots = []string{"consumer"}
		data = map[string]any{"consumer": map[string]any{"permissions": orEmpty(snap.Consumer)}}
	case strings.HasPrefix(name, "companies/") && snap.Company != nil:
		roots = []string{name}
		data = map[string]any{"companies": map[string]any{strings.TrimPrefix(name, "companies/"): snap.Company}}
	default:
		return nil, fmt.Errorf("unknown bundle %q", name)
	}

	b := opabundle.Bundle{Manifest: opabundle.Manifest{Revision: Revision(name, snap.Revision, policies)}, Modules: modules}
	if roots != nil {
		b.Manifest.Roots = &roots
	}
	// The signature hashes the data as plain JSON values, so structs go through JSON first.
	if err := roundTrip(data, &b.Data); err != nil {
		return nil, err
	}
	if err := b.GenerateSignature(s.config, s.KeyID, false); err != nil {
		return nil, fmt.Errorf("sign bundle %q: %w", name, err)
	}
	var buf bytes.Buffer
	// Ship the policy byte for byte: formatting would change what the revision hashed.
	if err := opabundle.NewWriter(&buf).DisableFormat(true).Write(b); err != nil {
		return nil, fmt.Errorf("write bundle %q: %w", name, err)
	}
	return buf.Bytes(), nil
}

func roundTrip(in any, out *map[string]any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// orEmpty keeps an empty set as {} rather than null, so the policy can index it.
func orEmpty[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}
