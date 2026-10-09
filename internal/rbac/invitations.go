package rbac

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
)

// E.164, the form Kratos stores phones in.
var e164 = regexp.MustCompile(`^\+[1-9][0-9]{6,14}$`)

type Invitation struct {
	ID          string     `json:"id"`
	CompanyID   string     `json:"company_id"`
	CompanyName string     `json:"company_name"`
	Phone       string     `json:"phone"`
	RoleIDs     []string   `json:"role_ids"`
	InvitedBy   string     `json:"invited_by"`
	Sub         *string    `json:"sub"`
	ExpiresAt   time.Time  `json:"expires_at"`
	AcceptedAt  *time.Time `json:"accepted_at"`
	CreatedAt   time.Time  `json:"created_at"`
	Status      string     `json:"status"`
}

func (i *Invitation) setStatus(now time.Time) {
	switch {
	case i.AcceptedAt != nil:
		i.Status = "accepted"
	case !now.Before(i.ExpiresAt):
		i.Status = "expired"
	default:
		i.Status = "pending"
	}
}

const invitationSelect = `
	SELECT i.id::text, i.company_id::text, c.name, i.phone, i.role_ids::text[], i.invited_by, i.sub,
	       i.expires_at, i.accepted_at, i.created_at, ''
	FROM invitations i JOIN companies c ON c.id = i.company_id`

// InvitationInput is the body of POST /v1/invitations.
type InvitationInput struct {
	Phone   string   `json:"phone"`
	RoleIDs []string `json:"role_ids"`
}

// CreateInvitation invites a phone number into the caller's company with the given roles. The
// IdP delivers the link; a person who already belongs to a company cannot be invited (one generic
// answer, whatever the company).
func (s *Service) CreateInvitation(ctx context.Context, c Caller, in InvitationInput) (Invitation, error) {
	if !e164.MatchString(in.Phone) {
		return Invitation{}, fail(KindInvalid, "invalid_phone", "phone must be in international format, like +8801712345678")
	}
	roleIDs := append([]string{}, slices.Compact(slices.Sorted(slices.Values(in.RoleIDs)))...)
	p, err := callerPower(ctx, s.DB, c)
	if err != nil {
		return Invitation{}, err
	}
	roles, err := loadRoles(ctx, s.DB, c.CompanyID, roleIDs)
	if err != nil {
		return Invitation{}, err
	}
	for _, id := range roleIDs {
		r, ok := roles[id]
		if !ok {
			return Invitation{}, fail(KindInvalid, "unknown_role", "unknown role %q", id)
		}
		if !p.covers(r) {
			return Invitation{}, escalation()
		}
	}

	sub, err := s.IdP.IdentityByPhone(ctx, in.Phone)
	if err != nil {
		slog.Error("idp lookup failed", "err", err)
		return Invitation{}, fail(KindUnavailable, "idp_unavailable", "the invitation could not be sent; try again")
	}
	if sub != "" {
		if company, err := s.companyOf(ctx, sub); err != nil {
			return Invitation{}, err
		} else if company != "" {
			return Invitation{}, fail(KindConflict, "cannot_invite", "this number cannot be invited")
		}
	}

	id := uuid.NewString()
	expires := s.Now().Add(s.InviteTTL).UTC().Truncate(time.Second)
	var companyName string
	err = s.tx(ctx, func(tx pgx.Tx) error {
		// A new invitation replaces any pending one for the same phone in this company.
		if _, err := tx.Exec(ctx, `
			UPDATE invitations SET expires_at = now()
			WHERE company_id = $1 AND phone = $2 AND accepted_at IS NULL AND expires_at > now()`, c.CompanyID, in.Phone); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO invitations (id, company_id, phone, role_ids, invited_by, expires_at)
			VALUES ($1, $2, $3, $4::uuid[], $5, $6)`, id, c.CompanyID, in.Phone, roleIDs, c.Sub, expires); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT name FROM companies WHERE id = $1`, c.CompanyID).Scan(&companyName)
	})
	if err != nil {
		return Invitation{}, err
	}

	if err := s.IdP.SendInvitation(ctx, idp.Invitation{ID: id, Phone: in.Phone, CompanyName: companyName, ExpiresAt: expires}); err != nil {
		slog.Error("idp send invitation failed", "err", err)
		if _, derr := s.DB.Exec(context.WithoutCancel(ctx), `DELETE FROM invitations WHERE id = $1`, id); derr != nil {
			slog.Error("could not delete unsent invitation", "id", id, "err", derr)
		}
		return Invitation{}, fail(KindUnavailable, "idp_unavailable", "the invitation could not be sent; try again")
	}
	s.Events.Publish(ctx, events.MemberInvited, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "invitation_id": id, "role_ids": roleIDs, "by": c.Sub,
	})
	return s.GetInvitation(ctx, id)
}

func (s *Service) ListInvitations(ctx context.Context, c Caller) ([]Invitation, error) {
	if _, err := callerPower(ctx, s.DB, c); err != nil {
		return nil, err
	}
	rows, err := s.DB.Query(ctx, invitationSelect+` WHERE i.company_id = $1 ORDER BY i.created_at DESC`, c.CompanyID)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Invitation])
	if err != nil {
		return nil, err
	}
	now := s.Now()
	for i := range list {
		list[i].setStatus(now)
	}
	return list, nil
}

// GetInvitation is for the IdP's invite page (internal API).
func (s *Service) GetInvitation(ctx context.Context, id string) (Invitation, error) {
	if uuid.Validate(id) != nil {
		return Invitation{}, notFound("invitation")
	}
	rows, err := s.DB.Query(ctx, invitationSelect+` WHERE i.id = $1`, id)
	if err != nil {
		return Invitation{}, err
	}
	inv, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Invitation])
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, notFound("invitation")
	} else if err != nil {
		return Invitation{}, err
	}
	inv.setStatus(s.Now())
	return inv, nil
}

// AcceptInvitation makes sub a member with the invited roles (those that still exist). Called by
// the IdP once the person has an identity.
func (s *Service) AcceptInvitation(ctx context.Context, id, sub string) error {
	if sub == "" || len(sub) > 200 {
		return fail(KindInvalid, "invalid_subject", "sub is required")
	}
	if uuid.Validate(id) != nil {
		return notFound("invitation")
	}
	var companyID string
	var roleIDs []string
	var version int64
	err := s.write(ctx, func(tx pgx.Tx) error {
		var expires time.Time
		var accepted *time.Time
		err := tx.QueryRow(ctx, `
			SELECT company_id::text, role_ids::text[], expires_at, accepted_at FROM invitations WHERE id = $1 FOR UPDATE`, id).
			Scan(&companyID, &roleIDs, &expires, &accepted)
		if errors.Is(err, pgx.ErrNoRows) {
			return notFound("invitation")
		} else if err != nil {
			return err
		}
		if accepted != nil {
			return fail(KindConflict, "already_accepted", "this invitation has already been used")
		}
		if !s.Now().Before(expires) {
			return fail(KindPrecondition, "expired", "this invitation has expired")
		}
		if err := tx.QueryRow(ctx, `INSERT INTO members (sub, company_id) VALUES ($1, $2) RETURNING authz_version`, sub, companyID).Scan(&version); err != nil {
			if isUniqueViolation(err) {
				return fail(KindConflict, "already_member", "this account already belongs to a company")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO member_roles (sub, company_id, role_id)
			SELECT $1, $2, id FROM roles WHERE company_id = $2 AND id = ANY($3::uuid[])`, sub, companyID, roleIDs); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE invitations SET accepted_at = now(), sub = $2 WHERE id = $1`, id, sub)
		return err
	}, func(ctx context.Context) error {
		return s.View.PutUserVersion(ctx, sub, version)
	})
	if err != nil {
		return err
	}
	s.Events.Publish(ctx, events.MemberAdded, companyID, map[string]any{
		"company_id": companyID, "sub": sub, "invitation_id": id, "role_ids": roleIDs,
	})
	return nil
}
