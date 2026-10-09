-- +goose Up

-- A member's authorization version: in their access token and in the gateway view (Redis). A
-- new value whenever their roles change, from one global sequence, so a version is never reused
-- (a user removed from one company and invited to another never matches an old token).
CREATE SEQUENCE authz_versions;
ALTER TABLE members ADD COLUMN authz_version bigint NOT NULL DEFAULT nextval('authz_versions');

-- +goose Down
ALTER TABLE members DROP COLUMN authz_version;
DROP SEQUENCE authz_versions;
