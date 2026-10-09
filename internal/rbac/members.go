package rbac

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/events"
)

type Member struct {
	Sub       string    `json:"sub"`
	RoleIDs   []string  `json:"role_ids"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) ListMembers(ctx context.Context, c Caller) ([]Member, error) {
	if _, err := callerPower(ctx, s.DB, c); err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, `
		SELECT m.sub, coalesce(array_agg(mr.role_id::text ORDER BY mr.role_id) FILTER (WHERE mr.role_id IS NOT NULL), '{}'), m.created_at
		FROM members m LEFT JOIN member_roles mr ON mr.sub = m.sub
		WHERE m.company_id = $1 GROUP BY m.sub ORDER BY m.created_at`, c.CompanyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Member])
}

// SetMemberRoles replaces a member's roles. Every role added or taken away must pass the
// escalation rule, and the company's last admin cannot lose the admin role.
func (s *Service) SetMemberRoles(ctx context.Context, c Caller, sub string, roleIDs []string) error {
	roleIDs = slices.Compact(slices.Sorted(slices.Values(roleIDs)))
	var added, removed []string
	var version int64
	err := s.write(ctx, func(tx pgx.Tx) error {
		p, err := callerPower(ctx, tx, c)
		if err != nil {
			return err
		}
		current, err := lockMember(ctx, tx, c.CompanyID, sub)
		if err != nil {
			return err
		}
		wanted, err := loadRoles(ctx, tx, c.CompanyID, roleIDs)
		if err != nil {
			return err
		}
		for _, id := range roleIDs {
			if _, ok := wanted[id]; !ok {
				return fail(KindInvalid, "unknown_role", "unknown role %q", id)
			}
			if !slices.Contains(current, id) {
				added = append(added, id)
			}
		}
		for _, id := range current {
			if !slices.Contains(roleIDs, id) {
				removed = append(removed, id)
			}
		}
		if len(added) == 0 && len(removed) == 0 {
			return nil
		}
		touched, err := loadRoles(ctx, tx, c.CompanyID, append(slices.Clone(added), removed...))
		if err != nil {
			return err
		}
		for _, r := range touched {
			if !p.covers(r) {
				return escalation()
			}
		}
		if err := keepAnAdmin(ctx, tx, c.CompanyID, sub, touched, removed); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM member_roles WHERE sub = $1`, sub); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO member_roles (sub, company_id, role_id) SELECT $1, $2, unnest($3::uuid[])`, sub, c.CompanyID, roleIDs); err != nil {
			return err
		}
		// A new version: the gateway refuses the member's current token until they refresh it.
		return tx.QueryRow(ctx, `UPDATE members SET authz_version = nextval('authz_versions') WHERE sub = $1 RETURNING authz_version`, sub).Scan(&version)
	}, func(ctx context.Context) error {
		if version == 0 {
			return nil
		}
		return s.View.PutUserVersion(ctx, sub, version)
	})
	if err != nil || (len(added) == 0 && len(removed) == 0) {
		return err
	}
	s.Events.Publish(ctx, events.MemberRolesChanged, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "sub": sub, "role_ids": roleIDs, "by": c.Sub,
	})
	return nil
}

// RemoveMember takes a user out of the company (they may then join or create another).
func (s *Service) RemoveMember(ctx context.Context, c Caller, sub string) error {
	err := s.write(ctx, func(tx pgx.Tx) error {
		p, err := callerPower(ctx, tx, c)
		if err != nil {
			return err
		}
		current, err := lockMember(ctx, tx, c.CompanyID, sub)
		if err != nil {
			return err
		}
		held, err := loadRoles(ctx, tx, c.CompanyID, current)
		if err != nil {
			return err
		}
		for _, r := range held {
			if !p.covers(r) {
				return escalation()
			}
		}
		if err := keepAnAdmin(ctx, tx, c.CompanyID, sub, held, current); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM members WHERE sub = $1`, sub)
		return err
	}, func(ctx context.Context) error {
		// No version: the gateway refuses every token of this subject.
		return s.View.DeleteUser(ctx, sub)
	})
	if err != nil {
		return err
	}
	s.Events.Publish(ctx, events.MemberRemoved, c.CompanyID, map[string]any{"company_id": c.CompanyID, "sub": sub, "by": c.Sub})
	return nil
}

// lockMember locks a member of the company and returns their role ids.
func lockMember(ctx context.Context, tx pgx.Tx, companyID, sub string) ([]string, error) {
	var locked string
	err := tx.QueryRow(ctx, `SELECT sub FROM members WHERE sub = $1 AND company_id = $2 FOR UPDATE`, sub, companyID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("member")
	} else if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT role_id::text FROM member_roles WHERE sub = $1 ORDER BY role_id`, sub)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// keepAnAdmin refuses to take the protected role from its last holder.
func keepAnAdmin(ctx context.Context, tx pgx.Tx, companyID, sub string, roles map[string]Role, removed []string) error {
	for _, id := range removed {
		if !roles[id].Protected {
			continue
		}
		// Lock the role row so two concurrent removals cannot both see "another holder".
		if _, err := tx.Exec(ctx, `SELECT 1 FROM roles WHERE id = $1 FOR UPDATE`, id); err != nil {
			return err
		}
		var others int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM member_roles WHERE role_id = $1 AND company_id = $2 AND sub <> $3`, id, companyID, sub).Scan(&others); err != nil {
			return err
		}
		if others == 0 {
			return fail(KindPrecondition, "last_admin", "the company must keep at least one %s", roles[id].Name)
		}
	}
	return nil
}
