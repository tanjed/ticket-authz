// Package catalogue defines a service's manifest (its permissions and APISIX route map) and
// validates it. Applying it to the database is rbac.Service.ApplyManifest.
package catalogue

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// Manifest is what a service's seed Job sends on every deploy.
type Manifest struct {
	Permissions []Permission `json:"permissions"`
	Routes      []Route      `json:"routes"`
}

type Permission struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	// Consumer puts the permission in the consumer set.
	Consumer bool `json:"consumer"`
}

// Route maps an APISIX route name to the one permission it requires, or marks it public.
type Route struct {
	Name       string `json:"name"`
	Permission string `json:"permission,omitempty"`
	Public     bool   `json:"public,omitempty"`
}

var (
	// resource:action, no API version.
	permissionKey = regexp.MustCompile(`^[a-z][a-z0-9_-]*:[a-z][a-z0-9_.-]*$`)
	serviceName   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	routeName     = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,199}$`)
)

// ValidService reports whether s is usable as a service name.
func ValidService(s string) bool { return serviceName.MatchString(s) }

// ValidPermissionKey reports whether k is a well-formed permission key.
func ValidPermissionKey(k string) bool { return permissionKey.MatchString(k) }

// Decode reads and validates a manifest. Unknown fields are refused so typos don't pass silently.
func Decode(r io.Reader) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("invalid manifest JSON: %w", err)
	}
	return m, m.Validate()
}

// Validate checks the manifest on its own; ownership conflicts need the database.
func (m Manifest) Validate() error {
	keys := make(map[string]bool, len(m.Permissions))
	for _, p := range m.Permissions {
		if !permissionKey.MatchString(p.Key) {
			return fmt.Errorf("permission %q: must look like resource:action (lowercase)", p.Key)
		}
		if keys[p.Key] {
			return fmt.Errorf("permission %q: listed twice", p.Key)
		}
		keys[p.Key] = true
	}
	names := make(map[string]bool, len(m.Routes))
	for _, r := range m.Routes {
		if !routeName.MatchString(r.Name) {
			return fmt.Errorf("route %q: invalid name", r.Name)
		}
		if names[r.Name] {
			return fmt.Errorf("route %q: listed twice", r.Name)
		}
		names[r.Name] = true
		switch {
		case r.Public && r.Permission != "":
			return fmt.Errorf("route %q: either public or a permission, not both", r.Name)
		case !r.Public && r.Permission == "":
			return fmt.Errorf("route %q: needs a permission or public: true", r.Name)
		case !r.Public && !keys[r.Permission]:
			return fmt.Errorf("route %q: permission %q is not in this manifest", r.Name, r.Permission)
		}
	}
	return nil
}

// PermissionKeys is the manifest's permission keys, in order (never nil).
func (m Manifest) PermissionKeys() []string {
	out := make([]string, 0, len(m.Permissions))
	for _, p := range m.Permissions {
		out = append(out, p.Key)
	}
	return out
}

// RouteNames is the manifest's route names, in order (never nil).
func (m Manifest) RouteNames() []string {
	out := make([]string, 0, len(m.Routes))
	for _, r := range m.Routes {
		out = append(out, r.Name)
	}
	return out
}
