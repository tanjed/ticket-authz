package invitation

import (
	"regexp"

	"github.com/tanjed/bus2/authz/internal/apperror"
)

// e164 is the phone form Kratos stores.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

func validPhone(phone string) error {
	if !e164.MatchString(phone) {
		return apperror.Fail(apperror.KindInvalid, "invalid_phone", "phone must be in international format, like +8801712345678")
	}
	return nil
}
