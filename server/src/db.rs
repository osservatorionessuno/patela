use crate::{HwSpecs, PREFIX_V4};
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
/// - relay by public key
/// - relay specs
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

#[derive(Debug)]
pub struct RelayRecord {
    pub name: String,
    pub ip_v4: String,
    pub ip_v6: String,
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

pub async fn get_node_key_and_nonce(
    pool: &SqlitePool,
    node_id: i64,
) -> anyhow::Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let mut conn = pool.acquire().await?;

    let res = sqlx::query!(
        r#"
SELECT aes_key, aes_nonce FROM nodes
WHERE id = ?
        "#,
        node_id
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok((res.aes_key, res.aes_nonce))
}

pub async fn update_node_aes_key(
    pool: &SqlitePool,
    node_id: i64,
    data: Vec<u8>,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;

    let _ = sqlx::query!(
        r#"
UPDATE nodes
SET aes_key = (?2)
WHERE id = (?1)
        "#,
        node_id,
        data
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
}

pub async fn update_node_aes_nonce(
    pool: &SqlitePool,
    node_id: i64,
    data: Vec<u8>,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;

    let _ = sqlx::query!(
        r#"
UPDATE nodes
SET aes_nonce = (?2)
WHERE id = (?1)
        "#,
        node_id,
        data
    )
    .execute(&mut *conn)
    .await?;

    Ok(())
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

    let res = sqlx::query_as!(
        RelayRecord,
        r#"
SELECT cheeses.name AS name, ip_v4, ip_v6 FROM relays
INNER JOIN cheeses ON relays.cheese_id = cheeses.id
WHERE node_id = ?
        "#,
        node_id
    )
    .fetch_all(&mut *conn)
    .await?;

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
    // more important: the loop on ipv6/48 prefix takes to long!
    if next_ip_v4.to_bits() >= net_v4.iter().last().unwrap().to_bits() {
        anyhow::bail!("No more ips availble in the netowrks");
    };

    Ok((next_ip_v4, next_ip_v6))
}

pub async fn insert_data(pool: &SqlitePool, relay_id: i64, data: Vec<u8>) -> anyhow::Result<i64> {
    let mut conn = pool.acquire().await?;

    let now = &Local::now().to_rfc3339();

    let id = sqlx::query!(
        r#"
INSERT INTO datas ( relay_id, date, data )
VALUES ( ?1, ?2, ?3 )
        "#,
        relay_id,
        now,
        data
    )
    .execute(&mut *conn)
    .await?
    .last_insert_rowid();

    Ok(id)
}

pub async fn get_data(
    pool: &SqlitePool,
    node_id: i64,
    relay_name: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut conn = pool.acquire().await?;

    let res = sqlx::query!(
        r#"
SELECT data FROM datas
INNER JOIN relays
ON datas.relay_id = relays.id
INNER JOIN cheeses
ON relays.cheese_id = cheeses.id
WHERE relays.node_id = ? AND cheeses.name = ?
        "#,
        node_id,
        relay_name
    )
    .fetch_one(&mut *conn)
    .await?;

    Ok(res.data.unwrap())
}

#[cfg(test)]
mod tests {
    use sqlx::SqlitePool;

    use crate::db::{FIRST_IP_4, FIRST_IP_6, create_node, find_next_ips};

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
}
