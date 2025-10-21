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
-- STEP 2: Add configuration support and netmask fields to relays
-- ==============================================================================

ALTER TABLE relays ADD COLUMN tor_conf TEXT;
ALTER TABLE relays ADD COLUMN v4_netmask INTEGER NOT NULL DEFAULT 24;
ALTER TABLE relays ADD COLUMN v6_netmask INTEGER NOT NULL DEFAULT 48;

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
    enabled     INTEGER             NOT NULL DEFAULT 0, -- Boolean: 1=enabled, 0=disabled (manual approval)
    ek_public   TEXT                NOT NULL UNIQUE,    -- TPM Endorsement Key (hex-encoded)
    ak_public   TEXT                NOT NULL,           -- TPM Attestation Key (hex-encoded)
    tor_conf    TEXT,                                   -- Node-specific tor config overrides
    node_conf   TEXT                                    -- Node-specific config
);

-- Note: V1 schema uses cert-based auth without TPM keys
-- V2 requires TPM attestation, so we cannot migrate existing nodes
-- All existing nodes will be dropped and must re-register with TPM attestation
-- The migration intentionally leaves nodes_new empty

-- Replace old table with new schema
DROP TABLE nodes;
ALTER TABLE nodes_new RENAME TO nodes;
