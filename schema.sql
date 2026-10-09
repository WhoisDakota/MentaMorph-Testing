-- Organizations schema (PostgreSQL 13+)
-- Users are NOT stored here; they live in Cognito and are referenced by their `sub` (a UUID).

BEGIN;

CREATE TABLE organizations (
    org_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text        NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    domain           text        NOT NULL,
    domain_verified  boolean     NOT NULL DEFAULT false,
    status           text        NOT NULL DEFAULT 'active'
                                 CHECK (status IN ('active', 'suspended', 'deleted')),
    created_by       uuid        NOT NULL,  -- Cognito sub of the creator
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),

    -- Enforce normalization at the DB level so nothing can slip past the app.
    CONSTRAINT domain_is_lowercase CHECK (domain = lower(domain)),
    CONSTRAINT domain_format CHECK (domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
);

-- One org per domain. Partial index so a soft-deleted org releases its domain.
CREATE UNIQUE INDEX organizations_domain_unique
    ON organizations (domain)
    WHERE status <> 'deleted';

CREATE TABLE memberships (
    org_id      uuid        NOT NULL REFERENCES organizations(org_id) ON DELETE RESTRICT,
    user_id     uuid        NOT NULL,  -- Cognito sub
    role        text        NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    created_by  uuid,
    PRIMARY KEY (org_id, user_id)
);

-- "Which orgs is this user in?"
CREATE INDEX memberships_user_id_idx ON memberships (user_id);

-- Retry safety for POST /organizations
CREATE TABLE idempotency_keys (
    user_id       uuid        NOT NULL,
    key           text        NOT NULL CHECK (length(key) BETWEEN 1 AND 128),
    request_hash  text        NOT NULL,
    org_id        uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, key)
);

-- Prune old keys with a scheduled job, e.g.:
--   DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours';

CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id      uuid        NOT NULL,
    actor_id    uuid        NOT NULL,
    action      text        NOT NULL,   -- e.g. 'org.created', 'member.role_changed'
    target_id   uuid,
    details     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_org_idx ON audit_log (org_id, created_at DESC);

-- Keep updated_at fresh
CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER organizations_set_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Never allow an org to lose its last owner (fires on delete or demotion).
CREATE FUNCTION prevent_last_owner_removal() RETURNS trigger AS $$
BEGIN
    IF OLD.role = 'owner'
       AND (TG_OP = 'DELETE' OR NEW.role <> 'owner')
       AND NOT EXISTS (
            SELECT 1 FROM memberships
            WHERE org_id = OLD.org_id AND role = 'owner' AND user_id <> OLD.user_id
       )
    THEN
        RAISE EXCEPTION 'Organization must keep at least one owner'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER memberships_protect_last_owner
    BEFORE UPDATE OR DELETE ON memberships
    FOR EACH ROW EXECUTE FUNCTION prevent_last_owner_removal();

COMMIT;
