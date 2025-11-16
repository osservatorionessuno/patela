-- OBSOLETE: This migration creates the legacy schema with certificate-based authentication.
-- It has been superseded by 20251014081633_v2.up.sql which implements TPM attestation.
-- This file is kept for historical reference only.

-- Add migration script here

-- Relay table
CREATE TABLE IF NOT EXISTS nodes
(
    id          INTEGER PRIMARY KEY NOT NULL,
    cert        VARCHAR(64)	    NOT NULL UNIQUE,    -- Sha256 digest of the public key
    first_seen  TEXT                NOT NULL,           -- Date in ISO 8601 format
    last_login  TEXT,                                   -- Date in ISO 8601 format (NULL until first auth)
    aes_key     BLOB                DEFAULT NULL,
    aes_nonce   BLOB                DEFAULT NULL
);

-- Specs table
CREATE TABLE IF NOT EXISTS specs
(
    id          INTEGER PRIMARY KEY NOT NULL,
    node_id	INTEGER             NOT NULL,
    date	TEXT                NOT NULL,
    specs       TEXT,
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

-- Relay table
CREATE TABLE IF NOT EXISTS relays
(
    id          INTEGER PRIMARY KEY NOT NULL,
    node_id	INTEGER             NOT NULL,
    cheese_id	INTEGER             NOT NULL,
    date	TEXT                NOT NULL UNIQUE,
    ip_v4       TEXT                NOT NULL UNIQUE,
    ip_v6       TEXT                NOT NULL UNIQUE,
    fingerprint TEXT,
    FOREIGN KEY(node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(cheese_id) REFERENCES cheeses(id) ON DELETE SET NULL
);

-- Data table
CREATE TABLE IF NOT EXISTS datas
(
    id          INTEGER PRIMARY KEY NOT NULL,
    relay_id	INTEGER             NOT NULL,
    date	TEXT                NOT NULL,
    data	BLOB,
    FOREIGN KEY(relay_id) REFERENCES relays(id) ON DELETE CASCADE
);

-- Cheeses table
CREATE TABLE IF NOT EXISTS cheeses
(
    id          INTEGER PRIMARY KEY NOT NULL,
    name	TEXT                NOT NULL,
    used	INTEGER             NOT NULL DEFAULT 0
);

-- Prefill cheeses table
INSERT INTO cheeses (name) VALUES
('murazzano'),
('montebore'),
('robiola'),
('seirass'),
('castelmagno'),
('stracchino'),
('gorgonzola'),
('taleggio') ,
('parmigiano') ,
('pecorino') ,
('stracciatella') ,
('squacquerone') ,
('asiago') ,
('caciocavallo') ,
('ricottasalata') ,
('canestrato') ,
('montasio') ,
('provolone') ,
('dolcesardo') ;

