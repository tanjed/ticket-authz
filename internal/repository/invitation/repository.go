package invitation

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/db/uow"
)

// Repo is what services use from this repository.
type Repo interface {
	// ExpirePending expires the company's pending invitations for the phone.
	ExpirePending(ctx context.Context, companyID, phone string) error
	Create(ctx context.Context, inv Invitation) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, companyID string) ([]Invitation, error)
	Get(ctx context.Context, id string) (Invitation, error)
	// LockPending loads an invitation for acceptance and locks it until the transaction ends.
	LockPending(ctx context.Context, id string) (PendingInvitation, error)
	MarkAccepted(ctx context.Context, id, sub string) error
}

var _ Repo = (*Repository)(nil)

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

// PendingInvitation is what accepting an invitation reads under lock.
type PendingInvitation struct {
	CompanyID  string
	RoleIDs    []string
	ExpiresAt  time.Time
	AcceptedAt *time.Time
}

// Repository is the invitations table.
type Repository struct{ db uow.Querier }

// invitationSelect reads an invitation with its company's name; the status is left empty (the
// service derives it).
const invitationSelect = `
	SELECT i.id::text, i.company_id::text, c.name, i.phone, i.role_ids::text[], i.invited_by, i.sub,
	       i.expires_at, i.accepted_at, i.created_at, ''
	FROM invitations i JOIN companies c ON c.id = i.company_id`

func (r *Repository) ExpirePending(ctx context.Context, companyID, phone string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `
		UPDATE invitations SET expires_at = now()
		WHERE company_id = $1 AND phone = $2 AND accepted_at IS NULL AND expires_at > now()`, companyID, phone)
	return err
}

func (r *Repository) Create(ctx context.Context, inv Invitation) error {
	_, err := r.db.Q(ctx).Exec(ctx, `
		INSERT INTO invitations (id, company_id, phone, role_ids, invited_by, expires_at)
		VALUES ($1, $2, $3, $4::uuid[], $5, $6)`, inv.ID, inv.CompanyID, inv.Phone, inv.RoleIDs, inv.InvitedBy, inv.ExpiresAt)
	return apperror.FromPG(err)
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `DELETE FROM invitations WHERE id = $1`, id)
	return err
}

func (r *Repository) List(ctx context.Context, companyID string) ([]Invitation, error) {
	rows, err := r.db.Q(ctx).Query(ctx, invitationSelect+` WHERE i.company_id = $1 ORDER BY i.created_at DESC`, companyID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Invitation])
}

func (r *Repository) Get(ctx context.Context, id string) (Invitation, error) {
	rows, err := r.db.Q(ctx).Query(ctx, invitationSelect+` WHERE i.id = $1`, id)
	if err != nil {
		return Invitation{}, err
	}
	inv, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Invitation])
	return inv, apperror.FromPG(err)
}

func (r *Repository) LockPending(ctx context.Context, id string) (PendingInvitation, error) {
	var p PendingInvitation
	err := r.db.Q(ctx).QueryRow(ctx, `
		SELECT company_id::text, role_ids::text[], expires_at, accepted_at FROM invitations WHERE id = $1 FOR UPDATE`, id).
		Scan(&p.CompanyID, &p.RoleIDs, &p.ExpiresAt, &p.AcceptedAt)
	return p, apperror.FromPG(err)
}

func (r *Repository) MarkAccepted(ctx context.Context, id, sub string) error {
	_, err := r.db.Q(ctx).Exec(ctx, `UPDATE invitations SET accepted_at = now(), sub = $2 WHERE id = $1`, id, sub)
	return err
}
