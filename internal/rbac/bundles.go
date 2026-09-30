package rbac

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RouteRule is one catalogue entry as OPA sees it.
type RouteRule struct {
	Permission string `json:"permission,omitempty"`
	Public     bool   `json:"public,omitempty"`
}

// RoleRule is one company role as OPA sees it.
type RoleRule struct {
	GrantsAll   bool            `json:"grants_all"`
	Permissions map[string]bool `json:"permissions"`
}

// CompanyRules is one company's bundle data.
type CompanyRules struct {
	Status string              `json:"status"`
	Roles  map[string]RoleRule `json:"roles"`
}

// Snapshot is a bundle's data at one revision. Only the field for its kind is set.
type Snapshot struct {
	Revision   int64
	Routes     map[string]RouteRule // catalogue
	Consumer   map[string]bool      // consumer
	Company    *CompanyRules        // companies/<id>
	CompanyIDs []string             // discovery
}

// BundleRevision returns a bundle's current revision; ok is false for an unknown bundle.
func (s *Service) BundleRevision(ctx context.Context, name string) (rev int64, ok bool, err error) {
	err = s.DB.QueryRow(ctx, `SELECT revision FROM bundle_revisions WHERE name = $1`, name).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return rev, err == nil, err
}

// BundleSnapshot reads a bundle's data and revision from one consistent snapshot.
func (s *Service) BundleSnapshot(ctx context.Context, name string) (snap Snapshot, ok bool, err error) {
	companyID, isCompany := strings.CutPrefix(name, "companies/")
	if isCompany && uuid.Validate(companyID) != nil {
		return Snapshot{}, false, nil
	}
	err = pgx.BeginTxFunc(ctx, s.DB, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT revision FROM bundle_revisions WHERE name = $1`, name).Scan(&snap.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		ok = true
		switch {
		case name == BundleDiscovery:
			rows, err := tx.Query(ctx, `SELECT id::text FROM companies ORDER BY id`)
			if err != nil {
				return err
			}
			snap.CompanyIDs, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		case name == BundleCatalogue:
			return catalogueRules(ctx, tx, &snap)
		case name == BundleConsumer:
			return consumerRules(ctx, tx, &snap)
		case isCompany:
			return companyRules(ctx, tx, companyID, &snap)
		default:
			ok = false
			return nil
		}
	})
	return snap, ok, err
}

func catalogueRules(ctx context.Context, tx pgx.Tx, snap *Snapshot) error {
	// A route whose permission was deprecated is left out, so it is denied.
	rows, err := tx.Query(ctx, `
		SELECT r.name, coalesce(r.permission_key, ''), r.public FROM routes r
		LEFT JOIN permissions p ON p.key = r.permission_key
		WHERE r.deprecated_at IS NULL AND (r.public OR p.deprecated_at IS NULL)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	snap.Routes = map[string]RouteRule{}
	for rows.Next() {
		var name string
		var rule RouteRule
		if err := rows.Scan(&name, &rule.Permission, &rule.Public); err != nil {
			return err
		}
		snap.Routes[name] = rule
	}
	return rows.Err()
}

func consumerRules(ctx context.Context, tx pgx.Tx, snap *Snapshot) error {
	rows, err := tx.Query(ctx, `SELECT key FROM permissions WHERE consumer AND deprecated_at IS NULL`)
	if err != nil {
		return err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	snap.Consumer = make(map[string]bool, len(keys))
	for _, k := range keys {
		snap.Consumer[k] = true
	}
	return nil
}

func companyRules(ctx context.Context, tx pgx.Tx, companyID string, snap *Snapshot) error {
	c := &CompanyRules{Roles: map[string]RoleRule{}}
	if err := tx.QueryRow(ctx, `SELECT status FROM companies WHERE id = $1`, companyID).Scan(&c.Status); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `
		SELECT r.id::text, r.grants_all, rp.permission_key FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.key = rp.permission_key
		WHERE r.company_id = $1 AND (rp.permission_key IS NULL OR p.deprecated_at IS NULL)`, companyID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var all bool
		var key *string
		if err := rows.Scan(&id, &all, &key); err != nil {
			return err
		}
		role, ok := c.Roles[id]
		if !ok {
			role = RoleRule{GrantsAll: all, Permissions: map[string]bool{}}
		}
		if key != nil {
			role.Permissions[*key] = true
		}
		c.Roles[id] = role
	}
	snap.Company = c
	return rows.Err()
}
