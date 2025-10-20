-- V2 Migration: TPM-based authentication and configuration hierarchy
-- This migration transforms the system from mTLS certificate-based auth to TPM attestation
-- and introduces a three-tier configuration system (global → node → relay)

-- ==============================================================================
-- STEP 1: Clean up legacy tables and columns
-- ==============================================================================

-- Drop backup-related columns (v2 removes key backup system)
ALTER TABLE nodes DROP COLUMN aes_key;
ALTER TABLE nodes DROP COLUMN aes_nonce;

-- Drop legacy fingerprint tracking
ALTER TABLE relays DROP COLUMN fingerprint;

-- Drop unused data storage table
DROP TABLE IF EXISTS datas;

-- ==============================================================================
-- STEP 2: Add configuration support to relays
-- ==============================================================================

ALTER TABLE relays ADD COLUMN tor_conf TEXT;

-- ==============================================================================
-- STEP 3: Create global configuration table
-- ==============================================================================

CREATE TABLE IF NOT EXISTS global_conf (
    id          INTEGER PRIMARY KEY NOT NULL,
    tor_conf    TEXT,
    node_conf   TEXT
);

CREATE INDEX IF NOT EXISTS idx_global_conf_id ON global_conf (id);

-- ==============================================================================
-- STEP 4: Migrate nodes table to TPM-based authentication
-- ==============================================================================
-- Replace mTLS certificate digest with TPM Endorsement Key (EK) as identity
-- EK public key becomes the immutable hardware-rooted node identity

-- Create new nodes table with TPM authentication schema
CREATE TABLE nodes_new (
    id          INTEGER PRIMARY KEY NOT NULL,
    first_seen  TEXT                NOT NULL,           -- ISO 8601 timestamp
    last_seen   TEXT                NOT NULL,           -- ISO 8601 timestamp
    active      INTEGER             NOT NULL DEFAULT 1, -- Boolean: 1=active, 0=inactive
    ek_public   TEXT                NOT NULL UNIQUE,    -- TPM Endorsement Key (hex-encoded)
    ak_public   TEXT                NOT NULL,           -- TPM Attestation Key (hex-encoded)
    tor_conf    TEXT,                                   -- Node-specific tor config overrides
    node_conf   TEXT                                    -- Node-specific config
);

-- Migrate existing nodes (only those with valid TPM keys)
-- This will drop any nodes without TPM keys (legacy certificate-only nodes)
INSERT INTO nodes_new (id, first_seen, last_seen, active, ek_public, ak_public, tor_conf, node_conf)
SELECT
    id,
    first_seen,
    last_seen,
    active,
    ek_public,
    ak_public,
    NULL,  -- tor_conf (new column)
    NULL   -- node_conf (new column)
FROM nodes
WHERE ek_public IS NOT NULL
  AND ek_public != ''
  AND ak_public IS NOT NULL
  AND ak_public != '';

-- Replace old table with new schema
DROP TABLE nodes;
ALTER TABLE nodes_new RENAME TO nodes;
