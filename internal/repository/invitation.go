package repository

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/service"
)

var _ service.InvitationRepo = (*Invitation)(nil)

// Invitation is the invitations table.
type Invitation struct{ q db.Querier }

func NewInvitation(q db.Querier) service.InvitationRepo { return &Invitation{q} }

// invitationSelect reads an invitation with its company's name; the status is left empty (the
// service derives it).
const invitationSelect = `
	SELECT i.id::text, i.company_id::text, c.name, i.phone, i.role_ids::text[], i.invited_by, i.sub,
	       i.expires_at, i.accepted_at, i.created_at, ''
	FROM invitations i JOIN companies c ON c.id = i.company_id`

func (r *Invitation) ExpirePending(ctx context.Context, companyID, phone string) error {
	_, err := r.q.Exec(ctx, `
		UPDATE invitations SET expires_at = now()
		WHERE company_id = $1 AND phone = $2 AND accepted_at IS NULL AND expires_at > now()`, companyID, phone)
	return err
}

func (r *Invitation) Create(ctx context.Context, inv service.Invitation) error {
	_, err := r.q.Exec(ctx, `
		INSERT INTO invitations (id, company_id, phone, role_ids, invited_by, expires_at)
		VALUES ($1, $2, $3, $4::uuid[], $5, $6)`, inv.ID, inv.CompanyID, inv.Phone, inv.RoleIDs, inv.InvitedBy, inv.ExpiresAt)
	return mapErr(err)
}

func (r *Invitation) Delete(ctx context.Context, id string) error {
	_, err := r.q.Exec(ctx, `DELETE FROM invitations WHERE id = $1`, id)
	return err
}

func (r *Invitation) List(ctx context.Context, companyID string) ([]service.Invitation, error) {
	rows, err := r.q.Query(ctx, invitationSelect+` WHERE i.company_id = $1 ORDER BY i.created_at DESC`, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[service.Invitation])
}

func (r *Invitation) Get(ctx context.Context, id string) (service.Invitation, error) {
	rows, err := r.q.Query(ctx, invitationSelect+` WHERE i.id = $1`, id)
	if err != nil {
		return service.Invitation{}, err
	}
	inv, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[service.Invitation])
	return inv, mapErr(err)
}

func (r *Invitation) LockPending(ctx context.Context, id string) (service.PendingInvitation, error) {
	var p service.PendingInvitation
	err := r.q.QueryRow(ctx, `
		SELECT company_id::text, role_ids::text[], expires_at, accepted_at FROM invitations WHERE id = $1 FOR UPDATE`, id).
		Scan(&p.CompanyID, &p.RoleIDs, &p.ExpiresAt, &p.AcceptedAt)
	return p, mapErr(err)
}

func (r *Invitation) MarkAccepted(ctx context.Context, id, sub string) error {
	_, err := r.q.Exec(ctx, `UPDATE invitations SET accepted_at = now(), sub = $2 WHERE id = $1`, id, sub)
	return err
}
