-- +goose Up

-- Company ownership moves to the Company service (../Company): companies, company users and
-- invitations are no longer Authz's. Authz keeps access only: roles, role assignments and each
-- user's authorization version.
--
-- DEV-ONLY, DESTRUCTIVE: this drops and recreates tables, losing every company, member, invitation
-- and role assignment. There is no production data yet, so no copy into Company is attempted.
-- The authz_versions sequence is kept untouched: versions are never reused (invariant 10).

DROP TABLE invitations;
DROP TABLE member_roles;
DROP TABLE members;

-- roles.company_id becomes a plain uuid (Company owns the company).
ALTER TABLE roles DROP CONSTRAINT roles_company_id_fkey;
DROP TABLE companies;

-- The composite key makes a cross-company assignment impossible at the database level. A user
-- belongs to one company, so (user_id, role_id) is the key.
CREATE TABLE user_roles (
  company_id uuid NOT NULL,
  user_id    text NOT NULL,
  role_id    uuid NOT NULL,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (role_id, company_id) REFERENCES roles (id, company_id) ON DELETE CASCADE
);
CREATE INDEX user_roles_role ON user_roles (role_id);
CREATE INDEX user_roles_company ON user_roles (company_id);

-- A user's authorization version: in the access token and in the gateway view (Redis). A new value
-- from the global authz_versions sequence whenever their roles change.
CREATE TABLE user_versions (
  user_id       text PRIMARY KEY,
  company_id    uuid NOT NULL,
  authz_version bigint NOT NULL
);

-- +goose Down
-- Irreversible: the dropped data is gone (dev-only migration).
SELECT 1;
