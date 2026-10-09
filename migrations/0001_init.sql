-- +goose Up

-- Catalogue: written only by service manifests (PUT /internal/v1/manifests/{service}).
CREATE TABLE permissions (
  key           text PRIMARY KEY,
  service       text NOT NULL,
  description   text NOT NULL DEFAULT '',
  consumer      boolean NOT NULL DEFAULT false,
  deprecated_at timestamptz
);

-- APISIX route name -> the one permission it requires, or public.
CREATE TABLE routes (
  name           text PRIMARY KEY,
  service        text NOT NULL,
  permission_key text REFERENCES permissions (key),
  public         boolean NOT NULL DEFAULT false,
  deprecated_at  timestamptz,
  CHECK ((permission_key IS NULL) = public)
);

CREATE TABLE companies (
  id         uuid PRIMARY KEY,
  name       text NOT NULL,
  status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE roles (
  id         uuid PRIMARY KEY,
  company_id uuid NOT NULL REFERENCES companies (id),
  name       text NOT NULL,
  protected  boolean NOT NULL DEFAULT false,
  grants_all boolean NOT NULL DEFAULT false,
  version    integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, company_id)
);
CREATE UNIQUE INDEX roles_company_name ON roles (company_id, lower(name));

CREATE TABLE role_permissions (
  role_id        uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
  permission_key text NOT NULL REFERENCES permissions (key),
  PRIMARY KEY (role_id, permission_key)
);

-- sub is the primary key: a user belongs to exactly one company.
CREATE TABLE members (
  sub        text PRIMARY KEY,
  company_id uuid NOT NULL REFERENCES companies (id),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (sub, company_id)
);
CREATE INDEX members_company ON members (company_id);

-- The composite keys make a cross-company assignment impossible at the database level.
CREATE TABLE member_roles (
  sub        text NOT NULL,
  company_id uuid NOT NULL,
  role_id    uuid NOT NULL,
  PRIMARY KEY (sub, role_id),
  FOREIGN KEY (sub, company_id) REFERENCES members (sub, company_id) ON DELETE CASCADE,
  FOREIGN KEY (role_id, company_id) REFERENCES roles (id, company_id)
);
CREATE INDEX member_roles_role ON member_roles (role_id);

CREATE TABLE invitations (
  id          uuid PRIMARY KEY,
  company_id  uuid NOT NULL REFERENCES companies (id),
  phone       text NOT NULL,
  role_ids    uuid[] NOT NULL,
  invited_by  text NOT NULL,
  sub         text,
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX invitations_company ON invitations (company_id);

-- +goose Down
DROP TABLE invitations, member_roles, members, role_permissions, roles, companies, routes, permissions;
