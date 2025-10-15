-- . Drop global_conf table and its index
DROP INDEX IF EXISTS idx_global_conf_id;
DROP TABLE IF EXISTS global_conf;

-- Add fingerprint column back to relays table
ALTER TABLE relays ADD COLUMN fingerprint TEXT;

-- Remove tor_conf column from nodes table
ALTER TABLE nodes DROP COLUMN tor_conf;

-- Remove tor_conf column from relays table
ALTER TABLE relays DROP COLUMN tor_conf;

-- Recreate datas table
CREATE TABLE IF NOT EXISTS datas
(
    id          INTEGER PRIMARY KEY NOT NULL,
    relay_id    INTEGER             NOT NULL,
    date        TEXT                NOT NULL,
    data        BLOB,
    FOREIGN KEY(relay_id) REFERENCES relays(id) ON DELETE CASCADE
);

-- Add back aes_key and aes_nonce columns to nodes table
ALTER TABLE nodes ADD COLUMN aes_key BLOB DEFAULT NULL;
ALTER TABLE nodes ADD COLUMN aes_nonce BLOB DEFAULT NULL;
