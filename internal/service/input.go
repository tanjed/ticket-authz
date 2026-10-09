package service

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/tanjed/bus2/authz/internal/catalogue"
)

// Input validation that needs no storage. Checks against the live catalogue happen in the
// services, inside their transaction.

// e164 is the phone form Kratos stores.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

// normalized trims the name, sorts and dedupes the permissions, and checks both are well formed.
func (in RoleInput) normalized() (RoleInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > 60 {
		return in, fail(KindInvalid, "invalid_name", "role name must be 1 to 60 characters")
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
	return fail(KindInvalid, "unknown_permission", "unknown permission %q", key)
}

func validPhone(phone string) error {
	if !e164.MatchString(phone) {
		return fail(KindInvalid, "invalid_phone", "phone must be in international format, like +8801712345678")
	}
	return nil
}

func validSubject(sub, field string) error {
	if sub == "" || len(sub) > 200 {
		return fail(KindInvalid, "invalid_subject", "%s is required", field)
	}
	return nil
}

func validCompanyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n == 0 || n > 100 {
		return "", fail(KindInvalid, "invalid_name", "company name must be 1 to 100 characters")
	}
	return name, nil
}

// dedupe sorts ids and drops duplicates, in place.
func dedupe(ids []string) []string {
	slices.Sort(ids)
	return slices.Compact(ids)
}
