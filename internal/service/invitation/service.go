package invitation

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/apperror"
	"github.com/tanjed/bus2/authz/internal/cache"
	"github.com/tanjed/bus2/authz/internal/db/uow"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
	companyrepo "github.com/tanjed/bus2/authz/internal/repository/company"
	invitationrepo "github.com/tanjed/bus2/authz/internal/repository/invitation"
	memberrepo "github.com/tanjed/bus2/authz/internal/repository/member"
	rolerepo "github.com/tanjed/bus2/authz/internal/repository/role"
	"github.com/tanjed/bus2/authz/internal/service/access"
)

// Service invites people into a company; the IdP delivers the link and calls back on
// acceptance.
type Service struct {
	uow         uow.Transactor
	cache       cache.Publisher
	events      events.Publisher
	idp         idp.Client
	ttl         time.Duration
	now         func() time.Time
	invitations invitationrepo.Repo
	members     memberrepo.Repo
	roles       rolerepo.Repo
	companies   companyrepo.Repo
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Create invites a phone number into the caller's company with the given roles. The IdP
// delivers the link; a person who already belongs to a company cannot be invited (one generic
// answer, whatever the company).
func (s *Service) Create(ctx context.Context, c access.Caller, in Input) (Invitation, error) {
	if err := validPhone(in.Phone); err != nil {
		return Invitation{}, err
	}
	roleIDs := append([]string{}, dedupe(slices.Clone(in.RoleIDs))...)
	if err := s.checkGrantable(ctx, c, roleIDs); err != nil {
		return Invitation{}, err
	}
	if err := s.checkInvitable(ctx, in.Phone); err != nil {
		return Invitation{}, err
	}

	inv := Invitation{ID: uuid.NewString(), CompanyID: c.CompanyID, Phone: in.Phone, RoleIDs: roleIDs, InvitedBy: c.Sub,
		ExpiresAt: s.now().Add(s.ttl).UTC().Truncate(time.Second)}
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		// A new invitation replaces any pending one for the same phone in this company.
		if err := s.invitations.ExpirePending(ctx, c.CompanyID, in.Phone); err != nil {
			return err
		}
		if err := s.invitations.Create(ctx, inv); err != nil {
			return err
		}
		var err error
		inv.CompanyName, err = s.companies.Name(ctx, c.CompanyID)
		return err
	})
	if err != nil {
		return Invitation{}, err
	}

	if err := s.idp.SendInvitation(ctx, idp.Invitation{ID: inv.ID, Phone: inv.Phone, CompanyName: inv.CompanyName, ExpiresAt: inv.ExpiresAt}); err != nil {
		slog.ErrorContext(ctx, "idp send invitation failed", "err", err)
		s.deleteUnsent(context.WithoutCancel(ctx), inv.ID)
		return Invitation{}, idpUnavailable()
	}
	s.events.Publish(ctx, events.MemberInvited, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "invitation_id": inv.ID, "role_ids": roleIDs, "by": c.Sub,
	})
	return s.Get(ctx, inv.ID)
}

// checkGrantable: the caller is a member, and may hand out every one of the roles.
func (s *Service) checkGrantable(ctx context.Context, c access.Caller, roleIDs []string) error {
	p, err := access.CallerPower(ctx, s.members, c)
	if err != nil {
		return err
	}
	roles, err := s.roles.Find(ctx, c.CompanyID, roleIDs)
	if err != nil {
		return err
	}
	for _, id := range roleIDs {
		role, ok := roles[id]
		if !ok {
			return apperror.Fail(apperror.KindInvalid, "unknown_role", "unknown role %q", id)
		}
		if !p.Covers(role) {
			return apperror.Escalation()
		}
	}
	return nil
}

// checkInvitable refuses a phone whose identity already belongs to a company.
func (s *Service) checkInvitable(ctx context.Context, phone string) error {
	sub, err := s.idp.IdentityByPhone(ctx, phone)
	if err != nil {
		slog.ErrorContext(ctx, "idp lookup failed", "err", err)
		return idpUnavailable()
	}
	if sub == "" {
		return nil
	}
	company, err := s.members.CompanyOf(ctx, sub)
	if err != nil {
		return err
	}
	if company != "" {
		return apperror.Fail(apperror.KindConflict, "cannot_invite", "this number cannot be invited")
	}
	return nil
}

// deleteUnsent removes an invitation the IdP could not deliver (logged, never returned).
func (s *Service) deleteUnsent(ctx context.Context, id string) {
	if err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		return s.invitations.Delete(ctx, id)
	}); err != nil {
		slog.ErrorContext(ctx, "could not delete unsent invitation", "id", id, "err", err)
	}
}

func (s *Service) List(ctx context.Context, c access.Caller) ([]Invitation, error) {
	if _, err := access.CallerPower(ctx, s.members, c); err != nil {
		return nil, err
	}
	list, err := s.invitations.List(ctx, c.CompanyID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	for i := range list {
		list[i].Status = status(list[i], now)
	}
	return list, nil
}

// Get is for the IdP's invite page (internal API).
func (s *Service) Get(ctx context.Context, id string) (Invitation, error) {
	if uuid.Validate(id) != nil {
		return Invitation{}, apperror.NotFound("invitation")
	}
	inv, err := s.invitations.Get(ctx, id)
	if errors.Is(err, apperror.ErrNotFound) {
		return Invitation{}, apperror.NotFound("invitation")
	}
	if err != nil {
		return Invitation{}, err
	}
	inv.Status = status(inv, s.now())
	return inv, nil
}

// Accept makes sub a member with the invited roles (those that still exist). Called by the IdP
// once the person has an identity.
func (s *Service) Accept(ctx context.Context, id, sub string) error {
	if err := access.ValidSubject(sub, "sub"); err != nil {
		return err
	}
	if uuid.Validate(id) != nil {
		return apperror.NotFound("invitation")
	}
	var pending invitationrepo.PendingInvitation
	var version int64
	err := s.uow.UnitOfWork(ctx, uow.Timeout, func(ctx context.Context) error {
		var err error
		pending, err = s.invitations.LockPending(ctx, id)
		if errors.Is(err, apperror.ErrNotFound) {
			return apperror.NotFound("invitation")
		} else if err != nil {
			return err
		}
		if pending.AcceptedAt != nil {
			return apperror.Fail(apperror.KindConflict, "already_accepted", "this invitation has already been used")
		}
		if !s.now().Before(pending.ExpiresAt) {
			return apperror.Fail(apperror.KindPrecondition, "expired", "this invitation has expired")
		}
		version, err = s.members.Create(ctx, sub, pending.CompanyID)
		if errors.Is(err, apperror.ErrDuplicate) {
			return apperror.Fail(apperror.KindConflict, "already_member", "this account already belongs to a company")
		} else if err != nil {
			return err
		}
		if err := s.members.AddExistingRoles(ctx, pending.CompanyID, sub, pending.RoleIDs); err != nil {
			return err
		}
		return s.invitations.MarkAccepted(ctx, id, sub)
	})
	if err == nil {
		s.cache.PutUserVersion(ctx, sub, version)
	}
	if err != nil {
		return err
	}
	s.events.Publish(ctx, events.MemberAdded, pending.CompanyID, map[string]any{
		"company_id": pending.CompanyID, "sub": sub, "invitation_id": id, "role_ids": pending.RoleIDs,
	})
	return nil
}

func idpUnavailable() error {
	return apperror.Fail(apperror.KindUnavailable, "idp_unavailable", "the invitation could not be sent; try again")
}
