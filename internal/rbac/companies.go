package rbac

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/tanjed/bus2/authz/internal/events"
)

// AdminRoleName is the protected role every company starts with.
const AdminRoleName = "Admin"

// RoleRef is a role as it appears in the token.
type RoleRef struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Claims is what the IdP puts in a provider's access token. AuthzVersion is the member's
// authorization version: the gateway refuses the token once the view holds another.
type Claims struct {
	CompanyID    string    `json:"company_id"`
	Roles        []RoleRef `json:"roles"`
	AuthzVersion int64     `json:"authz_version"`
}

// Claims resolves a subject's company and roles for a provider login.
func (s *Service) Claims(ctx context.Context, sub string) (Claims, error) {
	var c Claims
	var status string
	err := s.DB.QueryRow(ctx, `
		SELECT m.company_id::text, m.authz_version, c.status FROM members m JOIN companies c ON c.id = m.company_id WHERE m.sub = $1`, sub).
		Scan(&c.CompanyID, &c.AuthzVersion, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Claims{}, fail(KindNotFound, "not_a_member", "subject belongs to no company")
	} else if err != nil {
		return Claims{}, err
	}
	if status != "active" {
		return Claims{}, fail(KindForbidden, "company_suspended", "company is suspended")
	}
	rows, err := s.DB.Query(ctx, `
		SELECT r.id::text, r.name, r.version FROM member_roles mr JOIN roles r ON r.id = mr.role_id
		WHERE mr.sub = $1 ORDER BY r.name`, sub)
	if err != nil {
		return Claims{}, err
	}
	if c.Roles, err = pgx.CollectRows(rows, pgx.RowToStructByPos[RoleRef]); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// CreateCompany registers a company with its protected admin role held by adminSub. Idempotent
// per subject: if adminSub already belongs to a company, that company is returned (created=false).
func (s *Service) CreateCompany(ctx context.Context, name, adminSub string) (companyID string, created bool, err error) {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n == 0 || n > 100 {
		return "", false, fail(KindInvalid, "invalid_name", "company name must be 1 to 100 characters")
	}
	if adminSub == "" || len(adminSub) > 200 {
		return "", false, fail(KindInvalid, "invalid_subject", "admin_sub is required")
	}
	if id, err := s.companyOf(ctx, adminSub); err != nil || id != "" {
		return id, false, err
	}

	companyID, roleID := uuid.NewString(), uuid.NewString()
	var version int64
	err = s.write(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO companies (id, name) VALUES ($1, $2)`, companyID, name); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO roles (id, company_id, name, protected, grants_all) VALUES ($1, $2, $3, true, true)`,
			roleID, companyID, AdminRoleName); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO members (sub, company_id) VALUES ($1, $2) RETURNING authz_version`, adminSub, companyID).Scan(&version); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO member_roles (sub, company_id, role_id) VALUES ($1, $2, $3)`, adminSub, companyID, roleID)
		return err
	}, func(ctx context.Context) error {
		return errors.Join(
			s.View.PutCompany(ctx, companyID, "active"),
			s.View.PutRole(ctx, RoleView{CompanyID: companyID, RoleID: roleID, Permissions: []string{AllPermission}}),
			s.View.PutUserVersion(ctx, adminSub, version),
		)
	})
	if isUniqueViolation(err) {
		// A concurrent retry for the same subject won: answer with its company.
		id, err := s.companyOf(ctx, adminSub)
		return id, false, err
	}
	if err != nil {
		return "", false, err
	}
	s.Events.Publish(ctx, events.CompanyRegistered, companyID, map[string]any{
		"company_id": companyID, "name": name, "admin_sub": adminSub, "admin_role_id": roleID,
	})
	return companyID, true, nil
}

// SetCompanyStatus suspends or reactivates a company. The gateway denies every request of a
// suspended company's users at once, and they can no longer sign in to provider apps.
func (s *Service) SetCompanyStatus(ctx context.Context, companyID, status string) error {
	if status != "active" && status != "suspended" {
		return fail(KindInvalid, "invalid_status", "status must be active or suspended")
	}
	if uuid.Validate(companyID) != nil {
		return notFound("company")
	}
	changed := false
	return s.write(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE companies SET status = $2 WHERE id = $1 AND status <> $2`, companyID, status)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM companies WHERE id = $1)`, companyID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return notFound("company")
			}
			return nil
		}
		changed = true
		return nil
	}, func(ctx context.Context) error {
		if !changed {
			return nil
		}
		return s.View.PutCompany(ctx, companyID, status)
	})
}

func (s *Service) companyOf(ctx context.Context, sub string) (string, error) {
	var id string
	err := s.DB.QueryRow(ctx, `SELECT company_id::text FROM members WHERE sub = $1`, sub).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}
