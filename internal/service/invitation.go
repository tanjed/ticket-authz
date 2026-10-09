package service

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/tanjed/bus2/authz/internal/db"
	"github.com/tanjed/bus2/authz/internal/events"
	"github.com/tanjed/bus2/authz/internal/idp"
)

// Invitation statuses, derived from the invitation's times (never stored).
const (
	InvitationPending  = "pending"
	InvitationAccepted = "accepted"
	InvitationExpired  = "expired"
)

// InvitationService invites people into a company; the IdP delivers the link and calls back on
// acceptance.
type InvitationService struct {
	uow         UnitOfWork
	view        GatewayView
	events      events.Publisher
	idp         idp.Client
	ttl         time.Duration
	now         func() time.Time
	invitations InvitationRepoFactory
	members     MemberRepoFactory
	roles       RoleRepoFactory
	companies   CompanyRepoFactory
}

type invitationRepos struct {
	invitations InvitationRepo
	members     MemberRepo
	roles       RoleRepo
	companies   CompanyRepo
}

func NewInvitationService(uow UnitOfWork, view GatewayView, pub events.Publisher, c idp.Client, ttl time.Duration,
	invitations InvitationRepoFactory, members MemberRepoFactory, roles RoleRepoFactory, companies CompanyRepoFactory) *InvitationService {
	return &InvitationService{uow: uow, view: view, events: pub, idp: c, ttl: ttl, now: time.Now,
		invitations: invitations, members: members, roles: roles, companies: companies}
}

// SetClock replaces the clock (tests).
func (s *InvitationService) SetClock(now func() time.Time) { s.now = now }

func (s *InvitationService) bind(q db.Querier) invitationRepos {
	return invitationRepos{invitations: s.invitations(q), members: s.members(q), roles: s.roles(q), companies: s.companies(q)}
}

// Create invites a phone number into the caller's company with the given roles. The IdP
// delivers the link; a person who already belongs to a company cannot be invited (one generic
// answer, whatever the company).
func (s *InvitationService) Create(ctx context.Context, c Caller, in InvitationInput) (Invitation, error) {
	if err := validPhone(in.Phone); err != nil {
		return Invitation{}, err
	}
	roleIDs := append([]string{}, dedupe(slices.Clone(in.RoleIDs))...)
	if err := read(ctx, s.uow, s.bind, func(ctx context.Context, r invitationRepos) error {
		return s.checkGrantable(ctx, r, c, roleIDs)
	}); err != nil {
		return Invitation{}, err
	}
	if err := s.checkInvitable(ctx, in.Phone); err != nil {
		return Invitation{}, err
	}

	inv := Invitation{ID: uuid.NewString(), CompanyID: c.CompanyID, Phone: in.Phone, RoleIDs: roleIDs, InvitedBy: c.Sub,
		ExpiresAt: s.now().Add(s.ttl).UTC().Truncate(time.Second)}
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r invitationRepos) error {
		// A new invitation replaces any pending one for the same phone in this company.
		if err := r.invitations.ExpirePending(ctx, c.CompanyID, in.Phone); err != nil {
			return err
		}
		if err := r.invitations.Create(ctx, inv); err != nil {
			return err
		}
		var err error
		inv.CompanyName, err = r.companies.Name(ctx, c.CompanyID)
		return err
	}, nil)
	if err != nil {
		return Invitation{}, err
	}

	if err := s.idp.SendInvitation(ctx, idp.Invitation{ID: inv.ID, Phone: inv.Phone, CompanyName: inv.CompanyName, ExpiresAt: inv.ExpiresAt}); err != nil {
		slog.Error("idp send invitation failed", "err", err)
		s.deleteUnsent(context.WithoutCancel(ctx), inv.ID)
		return Invitation{}, idpUnavailable()
	}
	s.events.Publish(ctx, events.MemberInvited, c.CompanyID, map[string]any{
		"company_id": c.CompanyID, "invitation_id": inv.ID, "role_ids": roleIDs, "by": c.Sub,
	})
	return s.Get(ctx, inv.ID)
}

// checkGrantable: the caller is a member, and may hand out every one of the roles.
func (s *InvitationService) checkGrantable(ctx context.Context, r invitationRepos, c Caller, roleIDs []string) error {
	p, err := callerPower(ctx, r.members, c)
	if err != nil {
		return err
	}
	roles, err := r.roles.Find(ctx, c.CompanyID, roleIDs)
	if err != nil {
		return err
	}
	for _, id := range roleIDs {
		role, ok := roles[id]
		if !ok {
			return fail(KindInvalid, "unknown_role", "unknown role %q", id)
		}
		if !p.Covers(role) {
			return escalation()
		}
	}
	return nil
}

// checkInvitable refuses a phone whose identity already belongs to a company.
func (s *InvitationService) checkInvitable(ctx context.Context, phone string) error {
	sub, err := s.idp.IdentityByPhone(ctx, phone)
	if err != nil {
		slog.Error("idp lookup failed", "err", err)
		return idpUnavailable()
	}
	if sub == "" {
		return nil
	}
	return read(ctx, s.uow, s.bind, func(ctx context.Context, r invitationRepos) error {
		company, err := r.members.CompanyOf(ctx, sub)
		if err != nil {
			return err
		}
		if company != "" {
			return fail(KindConflict, "cannot_invite", "this number cannot be invited")
		}
		return nil
	})
}

// deleteUnsent removes an invitation the IdP could not deliver (logged, never returned).
func (s *InvitationService) deleteUnsent(ctx context.Context, id string) {
	if err := read(ctx, s.uow, s.bind, func(ctx context.Context, r invitationRepos) error {
		return r.invitations.Delete(ctx, id)
	}); err != nil {
		slog.Error("could not delete unsent invitation", "id", id, "err", err)
	}
}

func (s *InvitationService) List(ctx context.Context, c Caller) ([]Invitation, error) {
	var list []Invitation
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r invitationRepos) error {
		if _, err := callerPower(ctx, r.members, c); err != nil {
			return err
		}
		var err error
		list, err = r.invitations.List(ctx, c.CompanyID)
		return err
	})
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
func (s *InvitationService) Get(ctx context.Context, id string) (Invitation, error) {
	if uuid.Validate(id) != nil {
		return Invitation{}, notFound("invitation")
	}
	var inv Invitation
	err := read(ctx, s.uow, s.bind, func(ctx context.Context, r invitationRepos) error {
		var err error
		inv, err = r.invitations.Get(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return notFound("invitation")
		}
		return err
	})
	if err != nil {
		return Invitation{}, err
	}
	inv.Status = status(inv, s.now())
	return inv, nil
}

// Accept makes sub a member with the invited roles (those that still exist). Called by the IdP
// once the person has an identity.
func (s *InvitationService) Accept(ctx context.Context, id, sub string) error {
	if err := validSubject(sub, "sub"); err != nil {
		return err
	}
	if uuid.Validate(id) != nil {
		return notFound("invitation")
	}
	var pending PendingInvitation
	var version int64
	err := write(ctx, s.uow, s.bind, func(ctx context.Context, r invitationRepos) error {
		var err error
		pending, err = r.invitations.LockPending(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return notFound("invitation")
		} else if err != nil {
			return err
		}
		if pending.AcceptedAt != nil {
			return fail(KindConflict, "already_accepted", "this invitation has already been used")
		}
		if !s.now().Before(pending.ExpiresAt) {
			return fail(KindPrecondition, "expired", "this invitation has expired")
		}
		version, err = r.members.Create(ctx, sub, pending.CompanyID)
		if errors.Is(err, ErrDuplicate) {
			return fail(KindConflict, "already_member", "this account already belongs to a company")
		} else if err != nil {
			return err
		}
		if err := r.members.AddExistingRoles(ctx, pending.CompanyID, sub, pending.RoleIDs); err != nil {
			return err
		}
		return r.invitations.MarkAccepted(ctx, id, sub)
	}, func(ctx context.Context, _ invitationRepos) error {
		return s.view.PutUserVersion(ctx, sub, version)
	})
	if err != nil {
		return err
	}
	s.events.Publish(ctx, events.MemberAdded, pending.CompanyID, map[string]any{
		"company_id": pending.CompanyID, "sub": sub, "invitation_id": id, "role_ids": pending.RoleIDs,
	})
	return nil
}

// status is an invitation's status at now.
func status(i Invitation, now time.Time) string {
	switch {
	case i.AcceptedAt != nil:
		return InvitationAccepted
	case !now.Before(i.ExpiresAt):
		return InvitationExpired
	default:
		return InvitationPending
	}
}

func idpUnavailable() error {
	return fail(KindUnavailable, "idp_unavailable", "the invitation could not be sent; try again")
}
