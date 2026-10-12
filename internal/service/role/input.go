package role

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/catalogue"
)

// landingPath: empty, or an absolute in-app path (no scheme, no `//`).
var landingPath = regexp.MustCompile(`^/(?:[A-Za-z0-9\-._~][A-Za-z0-9\-._~/]*)?$`)

// normalized trims the name, sorts and dedupes the permissions, and checks both are well formed.
// Whether the permissions are live is checked against the catalogue, in the transaction.
func normalized(in Input) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > 60 {
		return in, apperror.Fail(apperror.KindInvalid, "invalid_name", "role name must be 1 to 60 characters")
	}
	if in.LandingPath != "" && (len(in.LandingPath) > 200 || !landingPath.MatchString(in.LandingPath) || strings.Contains(in.LandingPath, "//")) {
		return in, apperror.Fail(apperror.KindInvalid, "invalid_landing_path", "landing path must be empty or an absolute path of at most 200 characters")
	}
	in.Permissions = dedupe(slices.Clone(in.Permissions))
	for _, k := range in.Permissions {
		if !catalogue.ValidPermissionKey(k) {
			return in, unknownPermission(k)
		}
	}
	return in, nil
}

func unknownPermission(key string) error {
	return apperror.Fail(apperror.KindInvalid, "unknown_permission", "unknown permission %q", key)
}
