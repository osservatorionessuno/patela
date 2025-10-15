-- Drop aes_key and aes_nonce columns from nodes table
ALTER TABLE nodes DROP COLUMN aes_key;
ALTER TABLE nodes DROP COLUMN aes_nonce;

-- Drop fingerprint column from relays table
ALTER TABLE relays DROP COLUMN fingerprint;

-- Drop datas table
DROP TABLE IF EXISTS datas;

-- Add tor_conf field to relays table
ALTER TABLE relays ADD COLUMN tor_conf TEXT;

-- Add tor_conf and node_conf field to nodes table  
ALTER TABLE nodes ADD COLUMN tor_conf TEXT;
ALTER TABLE nodes ADD COLUMN node_conf TEXT;

-- Create global_conf table
CREATE TABLE IF NOT EXISTS global_conf
(
    id          INTEGER PRIMARY KEY NOT NULL,
    tor_conf    TEXT,
    node_conf   TEXT
);

-- Create index on global_conf table
CREATE INDEX IF NOT EXISTS idx_global_conf_id ON global_conf (id);
