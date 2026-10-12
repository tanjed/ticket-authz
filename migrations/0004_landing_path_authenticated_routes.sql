-- +goose Up

-- Where the provider UI lands users holding the role. Not part of the gateway view.
ALTER TABLE roles ADD COLUMN landing_path text NOT NULL DEFAULT '';

-- A route is a permission, public, or authenticated (any valid token): exactly one.
ALTER TABLE routes ADD COLUMN authenticated boolean NOT NULL DEFAULT false;
ALTER TABLE routes DROP CONSTRAINT routes_check;
ALTER TABLE routes ADD CONSTRAINT routes_one_mode CHECK (
  (permission_key IS NOT NULL)::int + public::int + authenticated::int = 1
);

-- +goose Down
ALTER TABLE routes DROP CONSTRAINT routes_one_mode;
DELETE FROM routes WHERE authenticated;
ALTER TABLE routes ADD CONSTRAINT routes_check CHECK ((permission_key IS NULL) = public);
ALTER TABLE routes DROP COLUMN authenticated;
ALTER TABLE roles DROP COLUMN landing_path;
