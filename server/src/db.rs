use crate::{HwSpecs, NodeConfig, tor_config::TorConfig};
use anyhow::{anyhow, bail};
use chrono::Local;
use ipnetwork::Ipv4Network;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    env,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

// TODO: extend db conf to handle multiple ip pools
lazy_static! {
    static ref FIRST_IP_4: Ipv4Addr = env::var("PATELA_FIRST_V4")
        .unwrap_or_else(|_| "64.190.76.10".to_string())
        .parse()
        .unwrap();
    static ref FIRST_IP_6: Ipv6Addr = env::var("PATELA_FIRST_V6")
        .unwrap_or_else(|_| "2001:67c:e28:1::102".to_string())
        .parse()
        .unwrap();
    static ref PREFIX_V4: u8 = env::var("PATELA_PREFIX_V4")
        .unwrap_or_else(|_| "24".to_string())
        .parse()
        .unwrap();
    static ref PREFIX_V6: u8 = env::var("PATELA_PREFIX_V6")
        .unwrap_or_else(|_| "48".to_string())
        .parse()
        .unwrap();
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: i64,
    pub first_seen: String,
    pub last_seen: String,
    pub enabled: bool,
    pub ek_public: String,
    pub ak_public: String,
}

// Define a struct for the relay data
#[derive(Debug, Serialize, Deserialize)]
pub struct RelayRecord {
    pub id: i64,
    pub node_id: i64,
    pub cheese_id: i64,
    pub name: String,
    pub date: String,
    pub ip_v4: String,
    pub ip_v6: String,
    pub v4_netmask: i64,
    pub v6_netmask: i64,
    pub tor_conf: Option<TorConfig>,
}

pub async fn create_node(
    pool: &SqlitePool,
    ek_public: &str,
    ak_public: &str,
) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    let now = &Local::now().to_rfc3339();

    let id = sqlx::query!(
        r#"
INSERT INTO nodes ( ek_public, ak_public, first_seen, last_seen )
VALUES ( ?1, ?2, ?3, ?4 )
        "#,
        ek_public,
        ak_public,
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
SELECT id, first_seen, last_seen, enabled as "enabled: bool", ek_public, ak_public FROM nodes
        "#,
    )
    .fetch_all(&mut *conn)
    .await?;

    Ok(res)
}

pub async fn get_or_create_node_by_ek(
    pool: &SqlitePool,
    ek_public: &str,
    ak_public: &str,
) -> anyhow::Result<NodeRecord> {
    let mut conn = pool.acquire().await?;

    // Try to find existing node by ek_public
    let existing = sqlx::query_as!(
        NodeRecord,
        r#"
SELECT id, first_seen, last_seen, enabled as "enabled: bool", ek_public, ak_public
FROM nodes
WHERE ek_public = ?1
        "#,
        ek_public
    )
    .fetch_optional(&mut *conn)
    .await?;

    if let Some(mut node) = existing {
        // Update last_seen and ak_public
        let now = Local::now().to_rfc3339();
        sqlx::query!(
            r#"
UPDATE nodes
SET last_seen = ?1, ak_public = ?2
WHERE id = ?3
            "#,
            now,
            ak_public,
            node.id
        )
        .execute(&mut *conn)
        .await?;

        node.last_seen = now;
        node.ak_public = ak_public.to_string();
        Ok(node)
    } else {
        // Create new node with ek_public and ak_public
        let now = Local::now().to_rfc3339();

        let id = sqlx::query!(
            r#"
INSERT INTO nodes (first_seen, last_seen, ek_public, ak_public)
VALUES (?1, ?2, ?3, ?4)
            "#,
            now,
            now,
            ek_public,
            ak_public
        )
        .execute(&mut *conn)
        .await?
        .last_insert_rowid();

        Ok(NodeRecord {
            id,
            first_seen: now.clone(),
            last_seen: now,
            enabled: false, // New nodes default to disabled, require manual approval
            ek_public: ek_public.to_string(),
            ak_public: ak_public.to_string(),
        })
    }
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

pub async fn enable_node(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;

    sqlx::query!(
        r#"
UPDATE nodes
SET enabled = 1
WHERE id = ?
        "#,
        id,
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

pub async fn disable_node(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;

    sqlx::query!(
        r#"
UPDATE nodes
SET enabled = 0
WHERE id = ?
        "#,
        id,
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

pub async fn create_relay(
    pool: &SqlitePool,
    node_id: i64,
    cheese_id: i64,
    ipv4: &str,
    ipv6: &str,
    v4_netmask: Option<i64>,
    v6_netmask: Option<i64>,
) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    let now = &Local::now().to_rfc3339();

    // Use default values if not provided
    let v4_netmask = v4_netmask.unwrap_or(24);
    let v6_netmask = v6_netmask.unwrap_or(48);

    let id = sqlx::query!(
        r#"
INSERT INTO relays ( node_id, cheese_id, date, ip_v4, ip_v6, v4_netmask, v6_netmask )
VALUES ( ?1, ?2, ?3, ?4, ?5, ?6, ?7 )
        "#,
        node_id,
        cheese_id,
        now,
        ipv4,
        ipv6,
        v4_netmask,
        v6_netmask
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

pub async fn get_relays_conf(pool: &SqlitePool, node_id: i64) -> anyhow::Result<Vec<RelayRecord>> {
    let mut conn = pool.acquire().await?;

    let rows = sqlx::query!(
        r#"
SELECT relays.id, relays.node_id, relays.cheese_id, relays.date,
       relays.ip_v4, relays.ip_v6, relays.v4_netmask, relays.v6_netmask,
       relays.tor_conf, cheeses.name AS name
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
                v4_netmask: row.v4_netmask,
                v6_netmask: row.v6_netmask,
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
        None => *FIRST_IP_4,
    };

    let net_v4 = Ipv4Network::new(*FIRST_IP_4, *PREFIX_V4)?;

    let next_ip_v6 = match ips_v6.last() {
        Some(last) => Ipv6Addr::from_bits(last.to_bits() + 1),
        None => *FIRST_IP_6,
    };

    // Check if there is room for another ip in the networks, we assume that ipv4 finish first and
    // more important: the mloop on ipv6/48 prefix takes to long!
    if next_ip_v4.to_bits() >= net_v4.iter().last().unwrap().to_bits() {
        anyhow::bail!("No more ips availble in the netowrks");
    };

    Ok((next_ip_v4, next_ip_v6))
}

/// Set or update the global default NodeConfig
pub async fn set_global_node_conf(pool: &SqlitePool, conf: &NodeConfig) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let json = serde_json::to_string(conf)?;

    // Global config always has id=1
    let _ = sqlx::query!(
        r#"
INSERT INTO global_conf (id, node_conf) VALUES (1, ?1)
ON CONFLICT(id) DO UPDATE SET node_conf = ?1
        "#,
        json
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Get the global default NodeConfig
pub async fn get_global_node_conf(pool: &SqlitePool) -> anyhow::Result<Option<NodeConfig>> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query!(
        r#"
SELECT node_conf FROM global_conf WHERE id = 1
        "#
    )
    .fetch_optional(&mut *conn)
    .await?;

    match row {
        Some(r) => match r.node_conf {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        },
        None => Ok(None),
    }
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

/// Set or update the NodeConfig override for a specific node
pub async fn set_node_node_conf(
    pool: &SqlitePool,
    node_id: i64,
    conf: &NodeConfig,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let json = serde_json::to_string(conf)?;

    let _ = sqlx::query!(
        r#"
UPDATE nodes SET node_conf = ?1 WHERE id = ?2
        "#,
        json,
        node_id
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

/// Get the TorConfig override for a specific node
pub async fn get_node_conf(pool: &SqlitePool, node_id: i64) -> anyhow::Result<Option<NodeConfig>> {
    let mut conn = pool.acquire().await?;

    let row = sqlx::query!(
        r#"
SELECT node_conf FROM nodes WHERE id = ?
        "#,
        node_id
    )
    .fetch_one(&mut *conn)
    .await?;

    match row.node_conf {
        Some(json) => Ok(Some(serde_json::from_str(&json)?)),
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

/// Get the fully resolved NodeConfig for a node, falling back to global if not set
pub async fn get_resolved_node_conf(pool: &SqlitePool, node_id: i64) -> anyhow::Result<NodeConfig> {
    // Try to get node-specific config first
    if let Some(conf) = get_node_conf(pool, node_id).await? {
        return Ok(conf);
    }

    // Fall back to global node config
    if let Some(conf) = get_global_node_conf(pool).await? {
        return Ok(conf);
    }

    // If neither exists, return an error
    anyhow::bail!("No node configuration found for node {}", node_id)
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ResolvedRelayRecord {
    pub id: i64,
    pub node_id: i64,
    pub cheese_id: i64,
    pub name: String,
    pub date: String,
    pub ip_v4: String,
    pub ip_v6: String,
    pub v4_netmask: i64,
    pub v6_netmask: i64,
    pub resolved_tor_conf: TorConfig,
}

impl std::fmt::Display for ResolvedRelayRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}\t\t{}\t{}", self.name, self.ip_v4, self.ip_v6)
    }
}

/// Get all relays for a specific node with their fully resolved Tor configurations
pub async fn get_resolved_node_relays_conf(
    pool: &SqlitePool,
    node_id: i64,
) -> anyhow::Result<Vec<ResolvedRelayRecord>> {
    // Get all relays for this node
    let relays = get_relays_conf(pool, node_id).await?;

    // Fetch global and node configs once to avoid redundant queries
    let global_conf = get_global_tor_conf(pool).await?;
    let node_conf = get_node_tor_conf(pool, node_id).await?;

    // Resolve configuration for each relay
    let mut resolved_relays = Vec::new();
    for relay in relays {
        // Merge global -> node -> relay configurations
        let resolved_tor_conf = merge_tor_configs(
            global_conf.as_ref(),
            node_conf.as_ref(),
            relay.tor_conf.as_ref(),
        );

        resolved_relays.push(ResolvedRelayRecord {
            id: relay.id,
            node_id: relay.node_id,
            cheese_id: relay.cheese_id,
            name: relay.name,
            date: relay.date,
            ip_v4: relay.ip_v4,
            ip_v6: relay.ip_v6,
            v4_netmask: relay.v4_netmask,
            v6_netmask: relay.v6_netmask,
            resolved_tor_conf,
        });
    }

    Ok(resolved_relays)
}

#[cfg(test)]
mod tests {
    use sqlx::SqlitePool;

    use crate::{HwSpecs, NetworkConf, NodeConfig, db::*, tor_config::TorConfigParser};

    #[sqlx::test]
    async fn test_create_node(pool: SqlitePool) -> sqlx::Result<()> {
        let _ = create_node(&pool, "ek_hex_test", "ak_hex_test").await;

        Ok(())
    }

    #[sqlx::test]
    async fn test_find_ips(pool: SqlitePool) -> sqlx::Result<()> {
        let (ipv4, ipv6) = find_next_ips(&pool).await.unwrap();

        assert_eq!(ipv4, *FIRST_IP_4);
        assert_eq!(ipv6, *FIRST_IP_6);

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
        let node_id = create_node(&pool, "test_ek_hex", "test_ak_hex")
            .await
            .unwrap();

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
INSERT INTO relays (node_id, cheese_id, date, ip_v4, ip_v6, v4_netmask, v6_netmask)
VALUES (?1, 1, '2025-01-01', '192.168.1.1', '::1', 24, 48)
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

    #[sqlx::test]
    async fn test_get_nodes(pool: SqlitePool) -> sqlx::Result<()> {
        // Create multiple nodes
        let _ = create_node(&pool, "ek1", "ak1").await.unwrap();
        let _ = create_node(&pool, "ek2", "ak2").await.unwrap();
        let _ = create_node(&pool, "ek3", "ak3").await.unwrap();

        let nodes = get_nodes(&pool).await.unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].ek_public, "ek1");
        assert_eq!(nodes[1].ek_public, "ek2");
        assert_eq!(nodes[2].ek_public, "ek3");

        Ok(())
    }

    #[sqlx::test]
    async fn test_get_or_create_node_by_ek(pool: SqlitePool) -> sqlx::Result<()> {
        let ek = "unique_ek_hex";
        let ak = "unique_ak_hex";

        // First call creates the node
        let node1 = get_or_create_node_by_ek(&pool, ek, ak).await.unwrap();
        assert_eq!(node1.ek_public, ek);
        assert_eq!(node1.ak_public, ak);
        assert_eq!(node1.enabled, false); // Should default to disabled

        // Second call returns the existing node
        let node2 = get_or_create_node_by_ek(&pool, ek, "new_ak_hex")
            .await
            .unwrap();
        assert_eq!(node2.id, node1.id);
        assert_eq!(node2.ek_public, ek);
        assert_eq!(node2.ak_public, "new_ak_hex"); // AK should be updated

        Ok(())
    }

    #[sqlx::test]
    async fn test_remove_node(pool: SqlitePool) -> sqlx::Result<()> {
        let ek = "to_delete_ek";
        let ak = "to_delete_ak";

        let node = get_or_create_node_by_ek(&pool, ek, ak).await.unwrap();

        // Node exists
        let found = get_or_create_node_by_ek(&pool, ek, ak).await;
        assert!(found.is_ok());

        // Remove the node
        remove_node(&pool, node.id).await.unwrap();

        // Node should be gone from the database
        let nodes = get_nodes(&pool).await.unwrap();
        assert!(nodes.iter().all(|n| n.id != node.id));

        Ok(())
    }

    #[sqlx::test]
    async fn test_find_ips_incremental(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "test_ek", "test_ak").await.unwrap();

        // Get first IPs
        let (ipv4_1, ipv6_1) = find_next_ips(&pool).await.unwrap();
        let (cheese_id_1, _) = allocate_cheese(&pool).await.unwrap();
        create_relay(
            &pool,
            node_id,
            cheese_id_1,
            &ipv4_1.to_string(),
            &ipv6_1.to_string(),
            None,
            None,
        )
        .await
        .unwrap();

        // Get next IPs - should be incremented
        let (ipv4_2, ipv6_2) = find_next_ips(&pool).await.unwrap();
        assert_eq!(ipv4_2.to_bits(), ipv4_1.to_bits() + 1);
        assert_eq!(ipv6_2.to_bits(), ipv6_1.to_bits() + 1);

        Ok(())
    }

    #[sqlx::test]
    async fn test_allocate_cheese(pool: SqlitePool) -> sqlx::Result<()> {
        let (cheese_id_1, name_1) = allocate_cheese(&pool).await.unwrap();
        assert!(cheese_id_1 > 0);
        assert!(!name_1.is_empty());

        // Allocate another cheese - should be different
        let (cheese_id_2, name_2) = allocate_cheese(&pool).await.unwrap();
        assert_ne!(cheese_id_1, cheese_id_2);
        assert_ne!(name_1, name_2);

        Ok(())
    }

    #[sqlx::test]
    async fn test_create_and_get_relay(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "relay_ek", "relay_ak").await.unwrap();
        let (cheese_id, cheese_name) = allocate_cheese(&pool).await.unwrap();

        let relay_id = create_relay(&pool, node_id, cheese_id, "10.0.0.1", "::1", None, None)
            .await
            .unwrap();
        assert!(relay_id > 0);

        // Get relay by name
        let found_relay_id = get_relay_by_name(&pool, node_id, &cheese_name)
            .await
            .unwrap();
        assert_eq!(relay_id, found_relay_id);

        Ok(())
    }

    #[sqlx::test]
    async fn test_get_relays_conf(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "multi_relay_ek", "multi_relay_ak")
            .await
            .unwrap();

        // Create multiple relays for this node
        let (cheese_id_1, _) = allocate_cheese(&pool).await.unwrap();
        let (cheese_id_2, _) = allocate_cheese(&pool).await.unwrap();

        create_relay(&pool, node_id, cheese_id_1, "10.0.0.1", "::1", None, None)
            .await
            .unwrap();
        create_relay(&pool, node_id, cheese_id_2, "10.0.0.2", "::2", None, None)
            .await
            .unwrap();

        let relays = get_relays_conf(&pool, node_id).await.unwrap();
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0].node_id, node_id);
        assert_eq!(relays[1].node_id, node_id);

        Ok(())
    }

    #[sqlx::test]
    async fn test_node_specs(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "spec_ek", "spec_ak").await.unwrap();

        let specs = HwSpecs {
            memory: 16_000_000_000,
            n_cpus: 8,
            cpu_freqz: 3_200_000_000,
            cpu_name: "Test CPU".to_string(),
        };

        let spec_id = create_node_spec(&pool, node_id, &specs).await.unwrap();
        assert!(spec_id > 0);

        let retrieved_specs = get_last_node_spec(&pool, node_id).await.unwrap();
        assert_eq!(retrieved_specs.memory, specs.memory);
        assert_eq!(retrieved_specs.n_cpus, specs.n_cpus);

        Ok(())
    }

    #[sqlx::test]
    async fn test_global_node_conf(pool: SqlitePool) -> sqlx::Result<()> {
        let conf = NodeConfig {
            network: NetworkConf {
                ipv4_gateway: "10.0.0.1".to_string(),
                ipv6_gateway: "fe80::1".to_string(),
                dns_server: Some("8.8.8.8".to_string()),
                interface_name: None,
            },
        };

        // Initially should be None
        let initial = get_global_node_conf(&pool).await.unwrap();
        assert!(initial.is_none());

        // Set global config
        set_global_node_conf(&pool, &conf).await.unwrap();

        // Retrieve and verify
        let retrieved = get_global_node_conf(&pool).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.network.ipv4_gateway, "10.0.0.1");
        assert_eq!(retrieved.network.ipv6_gateway, "fe80::1");
        assert_eq!(retrieved.network.dns_server, Some("8.8.8.8".to_string()));

        Ok(())
    }

    #[sqlx::test]
    async fn test_node_node_conf(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "conf_ek", "conf_ak").await.unwrap();

        let conf = NodeConfig {
            network: NetworkConf {
                ipv4_gateway: "192.168.1.1".to_string(),
                ipv6_gateway: "fe80::2".to_string(),
                dns_server: Some("1.1.1.1".to_string()),
                interface_name: Some("eth0".to_string()),
            },
        };

        // Initially should be None
        let initial = get_node_conf(&pool, node_id).await.unwrap();
        assert!(initial.is_none());

        // Set node config
        set_node_node_conf(&pool, node_id, &conf).await.unwrap();

        // Retrieve and verify
        let retrieved = get_node_conf(&pool, node_id).await.unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.network.ipv4_gateway, "192.168.1.1");

        Ok(())
    }

    #[sqlx::test]
    async fn test_global_tor_conf(pool: SqlitePool) -> sqlx::Result<()> {
        let torrc = r#"
SocksPort 9050
ControlPort 9051
DataDirectory /var/lib/tor
        "#;

        let conf = TorConfigParser::parse(torrc).unwrap();

        // Set global tor config
        set_global_tor_conf(&pool, &conf).await.unwrap();

        // Retrieve and verify
        let retrieved = get_global_tor_conf(&pool).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.unwrap().get_socks_port().unwrap().as_i64(),
            Some(9050)
        );

        Ok(())
    }

    #[sqlx::test]
    async fn test_node_tor_conf(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "tor_conf_ek", "tor_conf_ak")
            .await
            .unwrap();

        let torrc = r#"
SocksPort 9150
        "#;
        let conf = TorConfigParser::parse(torrc).unwrap();

        // Set node tor config
        set_node_tor_conf(&pool, node_id, &conf).await.unwrap();

        // Retrieve and verify
        let retrieved = get_node_tor_conf(&pool, node_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(
            retrieved.unwrap().get_socks_port().unwrap().as_i64(),
            Some(9150)
        );

        Ok(())
    }

    #[sqlx::test]
    async fn test_relay_tor_conf(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "relay_conf_ek", "relay_conf_ak")
            .await
            .unwrap();
        let (cheese_id, _) = allocate_cheese(&pool).await.unwrap();
        let relay_id = create_relay(&pool, node_id, cheese_id, "10.0.0.1", "::1", None, None)
            .await
            .unwrap();

        let torrc = r#"
ControlPort 9999
        "#;
        let conf = TorConfigParser::parse(torrc).unwrap();

        // Set relay tor config
        set_relay_tor_conf(&pool, relay_id, &conf).await.unwrap();

        // Retrieve and verify
        let retrieved = get_relay_tor_conf(&pool, relay_id).await.unwrap();
        assert!(retrieved.is_some());
        // Verify ControlPort is set to 9999
        let control_port = retrieved
            .unwrap()
            .directives
            .get("ControlPort")
            .and_then(|v| v.first())
            .and_then(|v| v.as_i64());
        assert_eq!(control_port, Some(9999));

        Ok(())
    }

    #[sqlx::test]
    async fn test_resolved_node_conf_fallback(pool: SqlitePool) -> sqlx::Result<()> {
        // Set global node config
        let global_conf = NodeConfig {
            network: NetworkConf {
                ipv4_gateway: "10.0.0.1".to_string(),
                ipv6_gateway: "fe80::1".to_string(),
                dns_server: Some("8.8.8.8".to_string()),
                interface_name: None,
            },
        };
        set_global_node_conf(&pool, &global_conf).await.unwrap();

        // Create a node without specific config
        let node_id = create_node(&pool, "fallback_ek", "fallback_ak")
            .await
            .unwrap();

        // Should fall back to global config
        let resolved = get_resolved_node_conf(&pool, node_id).await.unwrap();
        assert_eq!(resolved.network.ipv4_gateway, "10.0.0.1");

        // Now set node-specific config
        let node_conf = NodeConfig {
            network: NetworkConf {
                ipv4_gateway: "192.168.1.1".to_string(),
                ipv6_gateway: "fe80::2".to_string(),
                dns_server: Some("1.1.1.1".to_string()),
                interface_name: None,
            },
        };
        set_node_node_conf(&pool, node_id, &node_conf)
            .await
            .unwrap();

        // Should use node-specific config
        let resolved = get_resolved_node_conf(&pool, node_id).await.unwrap();
        assert_eq!(resolved.network.ipv4_gateway, "192.168.1.1");

        Ok(())
    }

    #[sqlx::test]
    async fn test_resolved_node_conf_no_config(pool: SqlitePool) -> sqlx::Result<()> {
        let node_id = create_node(&pool, "no_conf_ek", "no_conf_ak")
            .await
            .unwrap();

        // Should fail since there's no global or node-specific config
        let result = get_resolved_node_conf(&pool, node_id).await;
        assert!(result.is_err());

        Ok(())
    }

    #[sqlx::test]
    async fn test_resolved_relay_conf_from_real_torrc(pool: SqlitePool) -> sqlx::Result<()> {
        // Parse real torrc configuration as global config
        let global_torrc = r#"
Nickname testnode
AvoidDiskWrites 1
DisableAllSwap 1
RelayBandwidthRate 40 MB
RelayBandwidthBurst 80 MB
MaxMemInQueues 400 MB
ContactInfo email:info[]example.org url:https://example.org
MyFamily ABCD1234567890ABCDEF1234567890ABCDEF1234,1234567890ABCDEF1234567890ABCDEF12345678
ExitPolicy reject 0.0.0.0/8:*
ExitPolicy reject 169.254.0.0/16:*
ExitPolicy reject 10.0.0.0/8:*
ExitPolicy reject *:25
ExitPolicy accept *:*
ExitRelay 1
IPv6Exit 1
        "#;

        let global_conf = TorConfigParser::parse(global_torrc).unwrap();
        set_global_tor_conf(&pool, &global_conf).await.unwrap();

        // Create a node with node-specific override (disable AvoidDiskWrites)
        let node_id = create_node(&pool, "test_ek", "test_ak").await.unwrap();
        let node_torrc = r#"
AvoidDiskWrites 0
        "#;
        let node_conf = TorConfigParser::parse(node_torrc).unwrap();
        set_node_tor_conf(&pool, node_id, &node_conf).await.unwrap();

        // Create a relay with relay-specific bandwidth override
        let (cheese_id, _) = allocate_cheese(&pool).await.unwrap();
        let relay_id = create_relay(&pool, node_id, cheese_id, "10.0.0.1", "::1", None, None)
            .await
            .unwrap();

        let relay_torrc = r#"
RelayBandwidthBurst 150 MB
        "#;
        let relay_conf = TorConfigParser::parse(relay_torrc).unwrap();
        set_relay_tor_conf(&pool, relay_id, &relay_conf)
            .await
            .unwrap();

        // Get resolved config (should merge all three levels)
        let resolved = get_resolved_relay_conf(&pool, node_id, relay_id)
            .await
            .unwrap();

        // Verify merged configuration
        // AvoidDiskWrites should be 0 (node override)
        let avoid_disk = resolved.directives.get("AvoidDiskWrites").unwrap();
        assert_eq!(avoid_disk[0].as_bool(), Some(false));

        // RelayBandwidthBurst should be 150 MB (relay override)
        let relay_bw_burst = resolved.directives.get("RelayBandwidthBurst").unwrap();
        assert_eq!(relay_bw_burst[0].as_string(), Some("150 MB"));

        // Global config values should be present
        let nickname = resolved.directives.get("Nickname").unwrap();
        assert_eq!(nickname[0].as_string(), Some("testnode"));

        let relay_bw_rate = resolved.directives.get("RelayBandwidthRate").unwrap();
        assert_eq!(relay_bw_rate[0].as_string(), Some("40 MB"));

        let max_mem = resolved.directives.get("MaxMemInQueues").unwrap();
        assert_eq!(max_mem[0].as_string(), Some("400 MB"));

        // Verify ExitPolicy from global config
        let exit_policy = resolved.directives.get("ExitPolicy").unwrap();
        assert_eq!(exit_policy.len(), 5);
        assert_eq!(exit_policy[0].as_string(), Some("reject 0.0.0.0/8:*"));
        assert_eq!(exit_policy[4].as_string(), Some("accept *:*"));

        // Verify ContactInfo from global
        let contact_info = resolved.directives.get("ContactInfo").unwrap();
        assert!(contact_info[0].as_string().unwrap().contains("example.org"));

        // Verify MyFamily from global
        let my_family = resolved.directives.get("MyFamily").unwrap();
        let family_str = my_family[0].as_string().unwrap();
        assert!(family_str.contains("ABCD1234567890ABCDEF1234567890ABCDEF1234"));

        // Verify boolean values from global
        let exit_relay = resolved.directives.get("ExitRelay").unwrap();
        assert_eq!(exit_relay[0].as_bool(), Some(true));

        let ipv6_exit = resolved.directives.get("IPv6Exit").unwrap();
        assert_eq!(ipv6_exit[0].as_bool(), Some(true));

        Ok(())
    }

    #[sqlx::test]
    async fn test_get_resolved_node_relays_conf(pool: SqlitePool) -> sqlx::Result<()> {
        // Set up global configuration
        let global_torrc = r#"
SocksPort 9050
ControlPort 9051
DataDirectory /var/lib/tor
RelayBandwidthRate 40 MB
        "#;
        let global_conf = TorConfigParser::parse(global_torrc).unwrap();
        set_global_tor_conf(&pool, &global_conf).await.unwrap();

        // Create a node with node-specific configuration
        let node_id = create_node(&pool, "multi_relay_ek", "multi_relay_ak")
            .await
            .unwrap();
        let node_torrc = r#"
SocksPort 9150
AvoidDiskWrites 1
        "#;
        let node_conf = TorConfigParser::parse(node_torrc).unwrap();
        set_node_tor_conf(&pool, node_id, &node_conf).await.unwrap();

        // Create multiple relays with different configurations
        let (cheese_id_1, name_1) = allocate_cheese(&pool).await.unwrap();
        let (cheese_id_2, name_2) = allocate_cheese(&pool).await.unwrap();
        let (cheese_id_3, name_3) = allocate_cheese(&pool).await.unwrap();

        let relay_id_1 = create_relay(&pool, node_id, cheese_id_1, "10.0.0.1", "::1", None, None)
            .await
            .unwrap();
        let relay_id_2 = create_relay(&pool, node_id, cheese_id_2, "10.0.0.2", "::2", None, None)
            .await
            .unwrap();
        let _relay_id_3 = create_relay(&pool, node_id, cheese_id_3, "10.0.0.3", "::3", None, None)
            .await
            .unwrap();

        // Set relay-specific configuration for relay 1
        let relay_torrc_1 = r#"
ControlPort 10001
        "#;
        let relay_conf_1 = TorConfigParser::parse(relay_torrc_1).unwrap();
        set_relay_tor_conf(&pool, relay_id_1, &relay_conf_1)
            .await
            .unwrap();

        // Set relay-specific configuration for relay 2
        let relay_torrc_2 = r#"
ControlPort 10002
RelayBandwidthRate 80 MB
        "#;
        let relay_conf_2 = TorConfigParser::parse(relay_torrc_2).unwrap();
        set_relay_tor_conf(&pool, relay_id_2, &relay_conf_2)
            .await
            .unwrap();

        // Relay 3 has no specific configuration

        // Get all resolved relay configurations
        let resolved = get_resolved_node_relays_conf(&pool, node_id).await.unwrap();

        // Verify we got 3 relays
        assert_eq!(resolved.len(), 3);

        // Verify relay 1
        let relay_1 = resolved.iter().find(|r| r.name == name_1).unwrap();
        assert_eq!(relay_1.ip_v4, "10.0.0.1");
        assert_eq!(relay_1.ip_v6, "::1");
        // Should have ControlPort from relay override (10001)
        let cp1 = relay_1
            .resolved_tor_conf
            .directives
            .get("ControlPort")
            .unwrap();
        assert_eq!(cp1[0].as_i64(), Some(10001));
        // Should have SocksPort from node override (9150)
        let sp1 = relay_1
            .resolved_tor_conf
            .directives
            .get("SocksPort")
            .unwrap();
        assert_eq!(sp1[0].as_i64(), Some(9150));
        // Should have DataDirectory from global (/var/lib/tor)
        let dd1 = relay_1
            .resolved_tor_conf
            .directives
            .get("DataDirectory")
            .unwrap();
        assert_eq!(dd1[0].as_string(), Some("/var/lib/tor"));
        // Should have RelayBandwidthRate from global (40 MB)
        let rbr1 = relay_1
            .resolved_tor_conf
            .directives
            .get("RelayBandwidthRate")
            .unwrap();
        assert_eq!(rbr1[0].as_string(), Some("40 MB"));

        // Verify relay 2
        let relay_2 = resolved.iter().find(|r| r.name == name_2).unwrap();
        assert_eq!(relay_2.ip_v4, "10.0.0.2");
        assert_eq!(relay_2.ip_v6, "::2");
        // Should have ControlPort from relay override (10002)
        let cp2 = relay_2
            .resolved_tor_conf
            .directives
            .get("ControlPort")
            .unwrap();
        assert_eq!(cp2[0].as_i64(), Some(10002));
        // Should have RelayBandwidthRate from relay override (80 MB)
        let rbr2 = relay_2
            .resolved_tor_conf
            .directives
            .get("RelayBandwidthRate")
            .unwrap();
        assert_eq!(rbr2[0].as_string(), Some("80 MB"));

        // Verify relay 3 (no relay-specific config)
        let relay_3 = resolved.iter().find(|r| r.name == name_3).unwrap();
        assert_eq!(relay_3.ip_v4, "10.0.0.3");
        assert_eq!(relay_3.ip_v6, "::3");
        // Should have ControlPort from global (9051)
        let cp3 = relay_3
            .resolved_tor_conf
            .directives
            .get("ControlPort")
            .unwrap();
        assert_eq!(cp3[0].as_i64(), Some(9051));
        // Should have SocksPort from node override (9150)
        let sp3 = relay_3
            .resolved_tor_conf
            .directives
            .get("SocksPort")
            .unwrap();
        assert_eq!(sp3[0].as_i64(), Some(9150));
        // Should have AvoidDiskWrites from node override (1/true)
        let adw3 = relay_3
            .resolved_tor_conf
            .directives
            .get("AvoidDiskWrites")
            .unwrap();
        assert_eq!(adw3[0].as_bool(), Some(true));

        Ok(())
    }
}
