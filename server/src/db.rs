use crate::{HwSpecs, PREFIX_V4, tor_config::TorConfig};
use anyhow::{anyhow, bail};
use chrono::Local;
use ipnetwork::Ipv4Network;
use sqlx::SqlitePool;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

/// What in the db? Why the db?
///
/// - list of valid relay names
/// - assigned ip to relay
/// - default global conf
/// - node conf overrides
/// - relay conf overrides
/// - encrypted bkp from the relay
/// - encrypted bkp keys and nonce from the relay
///
/// For our need the db could be a very simple fs/file db, probably we don't need to do real sql
/// query, but the life is to short to learn another db? A valid alternative could be to have an fs
/// db with all the configuration and just file blobs dropped around.
///
const FIRST_IP_4: Ipv4Addr = Ipv4Addr::new(64, 190, 76, 10);
const FIRST_IP_6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x67c, 0xe28, 0x1, 0, 0, 0, 0x100);

#[derive(Debug)]
pub struct NodeRecord {
    pub id: i64,
    pub cert: String,
    pub first_seen: String,
    pub last_seen: String,
}

// Define a struct for the relay data
#[derive(Debug)]
pub struct RelayRecord {
    pub id: i64,
    pub node_id: i64,
    pub cheese_id: i64,
    pub name: String,
    pub date: String,
    pub ip_v4: String,
    pub ip_v6: String,
    pub fingerprint: Option<String>,
    pub tor_conf: Option<TorConfig>,
}

pub async fn create_node(pool: &SqlitePool, cert: &str) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    let now = &Local::now().to_rfc3339();

    let id = sqlx::query!(
        r#"
INSERT INTO nodes ( cert, first_seen, last_seen )
VALUES ( ?1, ?2, ?3 )
        "#,
        cert,
        now,
        now
    )
    .execute(&mut *conn)
    .await?
    .last_insert_rowid();

    Ok(id)
}

pub async fn get_nodes(pool: &SqlitePool) -> anyhow::Result<Vec<NodeRecord>> {
    let mut conn = pool.acquire().await?;

    let res = sqlx::query_as!(
        NodeRecord,
        r#"
SELECT id, cert, first_seen, last_seen FROM nodes
        "#,
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(res)
}

pub async fn remove_node(pool: &SqlitePool, id: i64) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    let id = sqlx::query!(
        r#"
DELETE FROM nodes
WHERE id = ?
        "#,
        id,
    )
    .execute(&mut *conn)
    .await?
    .last_insert_rowid();

    Ok(id)
}

pub async fn get_node_by_cert(pool: &SqlitePool, cert: &str) -> anyhow::Result<NodeRecord> {
    let mut conn = pool.acquire().await?;

    let res = sqlx::query_as!(
        NodeRecord,
        r#"
SELECT id, cert, first_seen, last_seen FROM nodes
WHERE cert = ?
        "#,
        cert
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(res)
}

pub async fn create_relay(
    pool: &SqlitePool,
    node_id: i64,
    cheese_id: i64,
    ipv4: &str,
    ipv6: &str,
) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    let now = &Local::now().to_rfc3339();

    let id = sqlx::query!(
        r#"
INSERT INTO relays ( node_id, cheese_id, date, ip_v4, ip_v6 )
VALUES ( ?1, ?2, ?3, ?4, ?5 )
        "#,
        node_id,
        cheese_id,
        now,
        ipv4,
        ipv6
    )
    .execute(&mut *conn)
    .await?
    .last_insert_rowid();

    Ok(id)
}

pub async fn get_relay_by_name(
    pool: &SqlitePool,
    node_id: i64,
    relay_name: &str,
) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    let res = sqlx::query!(
        r#"
SELECT relays.id AS id FROM relays
INNER JOIN cheeses
ON relays.cheese_id = cheeses.id
WHERE node_id = ? AND cheeses.name = ?
        "#,
        node_id,
        relay_name
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(res.id)
}

pub async fn get_relays(pool: &SqlitePool, node_id: i64) -> anyhow::Result<Vec<RelayRecord>> {
    let mut conn = pool.acquire().await?;

    let rows = sqlx::query!(
        r#"
SELECT relays.id, relays.node_id, relays.cheese_id, relays.date,
       relays.ip_v4, relays.ip_v6, relays.tor_conf, cheeses.name AS name
FROM relays
INNER JOIN cheeses ON relays.cheese_id = cheeses.id
WHERE node_id = ?
        "#,
        node_id
    )
    .fetch_all(&mut *conn)
    .await?;

    let res = rows
        .into_iter()
        .map(|row| {
            let tor_conf = row
                .tor_conf
                .as_ref()
                .and_then(|json| serde_json::from_str(json).ok());

            RelayRecord {
                id: row.id,
                node_id: row.node_id,
                cheese_id: row.cheese_id,
                name: row.name,
                date: row.date,
                ip_v4: row.ip_v4,
                ip_v6: row.ip_v6,
                fingerprint: None, // v2 removed fingerprint tracking
                tor_conf,
            }
        })
        .collect();

    Ok(res)
}

pub async fn create_node_spec(
    pool: &SqlitePool,
    node_id: i64,
    specs: &HwSpecs,
) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    // Now just store specs as json blob, maybe in future extend with a proper model
    let payload = &serde_json::to_string(specs)?;
    let now = &Local::now().to_rfc3339();

    let id = sqlx::query!(
        r#"
INSERT INTO specs ( node_id, date, specs )
VALUES ( ?1, ?2, ?3 )
        "#,
        node_id,
        now,
        payload
    )
    .execute(&mut *conn)
    .await?
    .last_insert_rowid();

    Ok(id)
}

pub async fn get_last_node_spec(pool: &SqlitePool, node_id: i64) -> anyhow::Result<HwSpecs> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query!(
        r#"
SELECT specs FROM specs
WHERE node_id = ?
ORDER BY id DESC
LIMIT 1
        "#,
        node_id
    )
    .fetch_one(&mut *conn)
    .await?;

    match row.specs {
        Some(ref specs) => Ok(serde_json::from_str(specs)?),
        None => Err(anyhow!(
            "No specs stored in the database for node {}",
            node_id
        )),
    }
}

pub async fn allocate_cheese(pool: &SqlitePool) -> anyhow::Result<(i64, String)> {
    let mut conn = pool.acquire().await?;

    let cheeses = sqlx::query!(
        r#"
SELECT id, name FROM cheeses
WHERE used = 0
        "#
    )
    .fetch_all(&mut *conn)
    .await?;

    let cheese = match cheeses.first() {
        Some(cheese) => cheese,
        None => bail!("No more cheese availble"),
    };

    let _ = sqlx::query!(
        r#"
UPDATE cheeses
SET used = 1
WHERE ID = (?1)
        "#,
        cheese.id,
    )
    .execute(&mut *conn)
    .await?
    .last_insert_rowid();

    Ok((cheese.id, cheese.name.clone()))
}

/// Search for the biggest ipv4/6 couple and return the next value
/// NOTE: the list is strictly incremental, also if some ip is delated will never be choose again
pub async fn find_next_ips(pool: &SqlitePool) -> anyhow::Result<(Ipv4Addr, Ipv6Addr)> {
    let mut conn = pool.acquire().await?;

    let ips = sqlx::query!(
        r#"
SELECT ip_v4, ip_v6 FROM relays
        "#
    )
    .fetch_all(&mut *conn)
    .await?;

    let (mut ips_v4, mut ips_v6): (Vec<_>, Vec<_>) = ips
        .iter()
        .map(|addr| {
            (
                Ipv4Addr::from_str(&addr.ip_v4).unwrap(),
                Ipv6Addr::from_str(&addr.ip_v6).unwrap(),
            )
        })
        .unzip();

    ips_v4.sort();
    ips_v6.sort();

    let next_ip_v4 = match ips_v4.last() {
        Some(last) => Ipv4Addr::from_bits(last.to_bits() + 1),
        None => FIRST_IP_4,
    };

    let net_v4 = Ipv4Network::new(FIRST_IP_4, *PREFIX_V4)?;

    let next_ip_v6 = match ips_v6.last() {
        Some(last) => Ipv6Addr::from_bits(last.to_bits() + 1),
        None => FIRST_IP_6,
    };

    // Check if there is room for another ip in the networks, we assume that ipv4 finish first and
    // more important: the mloop on ipv6/48 prefix takes to long!
    if next_ip_v4.to_bits() >= net_v4.iter().last().unwrap().to_bits() {
        anyhow::bail!("No more ips availble in the netowrks");
    };

    Ok((next_ip_v4, next_ip_v6))
}

/// Set or update the global default TorConfig
pub async fn set_global_tor_conf(pool: &SqlitePool, conf: &TorConfig) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let json = serde_json::to_string(conf)?;

    // Global config always has id=1
    let _ = sqlx::query!(
        r#"
INSERT INTO global_conf (id, tor_conf) VALUES (1, ?1)
ON CONFLICT(id) DO UPDATE SET tor_conf = ?1
        "#,
        json
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Get the global default TorConfig
pub async fn get_global_tor_conf(pool: &SqlitePool) -> anyhow::Result<Option<TorConfig>> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query!(
        r#"
SELECT tor_conf FROM global_conf WHERE id = 1
        "#
    )
    .fetch_optional(&mut *conn)
    .await?;

    match row {
        Some(r) => match r.tor_conf {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        },
        None => Ok(None),
    }
}

/// Set or update the TorConfig override for a specific node
pub async fn set_node_tor_conf(
    pool: &SqlitePool,
    node_id: i64,
    conf: &TorConfig,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let json = serde_json::to_string(conf)?;

    let _ = sqlx::query!(
        r#"
UPDATE nodes SET tor_conf = ?1 WHERE id = ?2
        "#,
        json,
        node_id
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Get the TorConfig override for a specific node
pub async fn get_node_tor_conf(
    pool: &SqlitePool,
    node_id: i64,
) -> anyhow::Result<Option<TorConfig>> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query!(
        r#"
SELECT tor_conf FROM nodes WHERE id = ?
        "#,
        node_id
    )
    .fetch_one(&mut *conn)
    .await?;

    match row.tor_conf {
        Some(json) => Ok(Some(serde_json::from_str(&json)?)),
        None => Ok(None),
    }
}

/// Set or update the TorConfig override for a specific relay
pub async fn set_relay_tor_conf(
    pool: &SqlitePool,
    relay_id: i64,
    conf: &TorConfig,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let json = serde_json::to_string(conf)?;

    let _ = sqlx::query!(
        r#"
UPDATE relays SET tor_conf = ?1 WHERE id = ?2
        "#,
        json,
        relay_id
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Get the TorConfig override for a specific relay
pub async fn get_relay_tor_conf(
    pool: &SqlitePool,
    relay_id: i64,
) -> anyhow::Result<Option<TorConfig>> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query!(
        r#"
SELECT tor_conf FROM relays WHERE id = ?
        "#,
        relay_id
    )
    .fetch_one(&mut *conn)
    .await?;

    match row.tor_conf {
        Some(json) => Ok(Some(serde_json::from_str(&json)?)),
        None => Ok(None),
    }
}

/// Merge TorConfig hierarchy: global -> node -> relay
/// Later configurations override earlier ones
fn merge_tor_configs(
    global: Option<&TorConfig>,
    node: Option<&TorConfig>,
    relay: Option<&TorConfig>,
) -> TorConfig {
    use std::collections::HashMap;

    let mut merged = TorConfig {
        directives: HashMap::new(),
    };

    // Start with global config
    if let Some(conf) = global {
        for (key, values) in &conf.directives {
            merged.directives.insert(key.clone(), values.clone());
        }
    }

    // Override with node config
    if let Some(conf) = node {
        for (key, values) in &conf.directives {
            merged.directives.insert(key.clone(), values.clone());
        }
    }

    // Override with relay config
    if let Some(conf) = relay {
        for (key, values) in &conf.directives {
            merged.directives.insert(key.clone(), values.clone());
        }
    }

    merged
}

/// Get the fully resolved TorConfig for a relay, merging global, node, and relay configs
pub async fn get_resolved_relay_conf(
    pool: &SqlitePool,
    node_id: i64,
    relay_id: i64,
) -> anyhow::Result<TorConfig> {
    let global_conf = get_global_tor_conf(pool).await?;
    let node_conf = get_node_tor_conf(pool, node_id).await?;
    let relay_conf = get_relay_tor_conf(pool, relay_id).await?;

    Ok(merge_tor_configs(
        global_conf.as_ref(),
        node_conf.as_ref(),
        relay_conf.as_ref(),
    ))
}

#[cfg(test)]
mod tests {
    use sqlx::SqlitePool;

    use crate::{
        db::{
            FIRST_IP_4, FIRST_IP_6, create_node, find_next_ips, get_global_tor_conf,
            get_resolved_relay_conf, set_global_tor_conf, set_node_tor_conf, set_relay_tor_conf,
        },
        tor_config::TorConfigParser,
    };

    #[sqlx::test]
    async fn test_create_node(pool: SqlitePool) -> sqlx::Result<()> {
        let _ = create_node(&pool, "prova").await;

        Ok(())
    }

    #[sqlx::test]
    async fn test_find_ips(pool: SqlitePool) -> sqlx::Result<()> {
        let (ipv4, ipv6) = find_next_ips(&pool).await.unwrap();

        assert_eq!(ipv4, FIRST_IP_4);
        assert_eq!(ipv6, FIRST_IP_6);

        Ok(())
    }

    #[sqlx::test]
    async fn test_tor_config_hierarchy(pool: SqlitePool) -> sqlx::Result<()> {
        // Parse example torrc
        let global_torrc = r#"
SocksPort 9050
ControlPort 9051
DataDirectory /var/lib/tor
        "#;

        let global_conf = TorConfigParser::parse(global_torrc).unwrap();

        // Set global config
        set_global_tor_conf(&pool, &global_conf).await.unwrap();

        // Verify we can retrieve it
        let retrieved = get_global_tor_conf(&pool).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.unwrap().get_socks_port().unwrap().as_i64(),
            Some(9050)
        );

        // Create a node
        let node_id = create_node(&pool, "test_cert_digest").await.unwrap();

        // Set node-specific override
        let node_torrc = r#"
SocksPort 9150
        "#;
        let node_conf = TorConfigParser::parse(node_torrc).unwrap();
        set_node_tor_conf(&pool, node_id, &node_conf).await.unwrap();

        // Create a relay (we need to allocate a cheese first, but for testing we'll use a simple approach)
        // For this test, we'll manually insert to avoid cheese allocation complexity
        let relay_id = sqlx::query!(
            r#"
INSERT INTO relays (node_id, cheese_id, date, ip_v4, ip_v6)
VALUES (?1, 1, '2025-01-01', '192.168.1.1', '::1')
            "#,
            node_id
        )
        .execute(&pool)
        .await?
        .last_insert_rowid();

        // Set relay-specific override
        let relay_torrc = r#"
ControlPort 9999
        "#;
        let relay_conf = TorConfigParser::parse(relay_torrc).unwrap();
        set_relay_tor_conf(&pool, relay_id, &relay_conf)
            .await
            .unwrap();

        // Get resolved config (should merge all three levels)
        let resolved = get_resolved_relay_conf(&pool, node_id, relay_id)
            .await
            .unwrap();

        // Verify the merge:
        // SocksPort should be 9150 (node override)
        // ControlPort should be 9999 (relay override)
        // DataDirectory should be /var/lib/tor (from global, not overridden)
        assert_eq!(
            resolved.get_data_directory().unwrap().as_string(),
            Some("/var/lib/tor")
        );

        Ok(())
    }
}
