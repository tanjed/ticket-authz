package role

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/catalogue"
)

// normalized trims the name, sorts and dedupes the permissions, and checks both are well formed.
// Whether the permissions are live is checked against the catalogue, in the transaction.
func normalized(in Input) (Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > 60 {
		return in, apperror.Fail(apperror.KindInvalid, "invalid_name", "role name must be 1 to 60 characters")
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
