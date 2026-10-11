package member

import (
	"context"
	"slices"

	"github.com/tanjed/bus2/authz/internal/apperror"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
)

// diff is what going from current to wanted adds and removes.
func diff(current, wanted []string) (added, removed []string) {
	for _, id := range wanted {
		if !slices.Contains(current, id) {
			added = append(added, id)
		}
	}
	for _, id := range current {
		if !slices.Contains(wanted, id) {
			removed = append(removed, id)
		}
	}
	return added, removed
}

// keepAnAdmin refuses to take the protected role from its last holder. The role is locked first,
// so two concurrent removals cannot both see "another holder".
func (s *Service) keepAnAdmin(ctx context.Context, companyID, sub string, roles map[string]rolerepo.Role, removed []string) error {
	for _, id := range removed {
		if !roles[id].Protected {
			continue
		}
		if _, err := s.roles.Lock(ctx, companyID, id); err != nil {
			return err
		}
		others, err := s.members.OtherHolders(ctx, companyID, id, sub)
		if err != nil {
			return err
		}
		if others == 0 {
			return apperror.Fail(apperror.KindPrecondition, "last_admin", "the company must keep at least one %s", roles[id].Name)
		}
	}
	return nil
}
