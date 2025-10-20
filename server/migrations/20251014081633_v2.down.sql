-- V2 Migration Rollback: Revert to mTLS certificate-based authentication
-- WARNING: This will drop all TPM-authenticated nodes!

-- ==============================================================================
-- STEP 1: Recreate nodes table with certificate-based authentication
-- ==============================================================================

CREATE TABLE nodes_old (
    id          INTEGER PRIMARY KEY NOT NULL,
    cert        VARCHAR(64)         NOT NULL UNIQUE,    -- SHA256 digest of client certificate
    active      INTEGER             NOT NULL DEFAULT 1,
    first_seen  TEXT                NOT NULL,
    last_seen   TEXT                NOT NULL,
    aes_key     BLOB                DEFAULT NULL,
    aes_nonce   BLOB                DEFAULT NULL
);

-- Migrate back existing nodes (this will LOSE TPM authentication data!)
INSERT INTO nodes_old (id, cert, active, first_seen, last_seen)
SELECT
    id,
    substr(ek_public, 1, 64),  -- Use EK hash as cert placeholder
    active,
    first_seen,
    last_seen
FROM nodes;

DROP TABLE nodes;
ALTER TABLE nodes_old RENAME TO nodes;

-- ==============================================================================
-- STEP 2: Drop configuration hierarchy
-- ==============================================================================

DROP INDEX IF EXISTS idx_global_conf_id;
DROP TABLE IF EXISTS global_conf;

ALTER TABLE relays DROP COLUMN tor_conf;

-- ==============================================================================
-- STEP 3: Restore legacy columns
-- ==============================================================================

ALTER TABLE relays ADD COLUMN fingerprint TEXT;

-- ==============================================================================
-- STEP 4: Recreate legacy data storage table
-- ==============================================================================

CREATE TABLE IF NOT EXISTS datas (
    id          INTEGER PRIMARY KEY NOT NULL,
    relay_id    INTEGER             NOT NULL,
    date        TEXT                NOT NULL,
    data        BLOB,
    FOREIGN KEY(relay_id) REFERENCES relays(id) ON DELETE CASCADE
);
