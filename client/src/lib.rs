include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use crate::tpm::*;
use anyhow::Context;
use bincode::{Decode, Encode};
use etc_passwd::Passwd;
use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use nftnl::{
    Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
    expr::{Immediate, Nat, NatType, Register},
    nft_expr,
    nftnl_sys::libc,
};
use patela_server::{HwSpecs, db::ResolvedRelayRecord, tor_config::TorValue};
use pem::{EncodeConfig, Pem, encode_config};
use rsa::{
    BigUint,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    traits::PrivateKeyParts,
};
use rtnetlink::{
    LinkUnspec, RouteMessageBuilder,
    packet_route::{
        AddressFamily,
        address::AddressAttribute,
        link::{LinkAttribute, LinkExtentMask},
    },
};
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::chown,
    path::Path,
};
use sysinfo::System;
use tss_esapi::Context as TpmContext;
use tss_esapi::handles::NvIndexHandle;

pub mod api;
pub mod tpm;

const NFT_TABLE_NAME: &CStr = c"patela";
const MANGLE_CHAIN_NAME: &CStr = c"mangle";
const MANGLE_CHAIN_PRIORITY: i32 = libc::NF_IP_PRI_MANGLE;
const NAT_CHAIN_NAME: &CStr = c"nat";
pub const TOR_INSTANCE_LIB_DIR: &str = "/var/lib/tor-instances";
const TOR_MASTER_KEY_NAME: &str = "ed25519_master_id_secret_key";
const TOR_RSA_KEY_NAME: &str = "secret_id_key";
const TOR_ED25519_HEADER: &[u8] = b"== ed25519v1-secret: type0 ==\x00\x00\x00";
const TOR_FAMILY_KEY_HEADER: &[u8] = b"== ed25519v1-secret: fmly-id ==\x00";
const TOR_FAMILY_KEY_NAME: &str = "osservatorionessuno.secret_family_key";
// 65537, see: https://spec.torproject.org/tor-spec/preliminaries.html#ciphers
const TOR_RSA_EXPONENT: &[u8] = &[0x01, 0x00, 0x01];

pub fn collect_specs() -> anyhow::Result<HwSpecs> {
    let sys = System::new_all();
    let cpu = sys.cpus().first().context("Unable to get CPU info")?;

    Ok(HwSpecs {
        n_cpus: sys.cpus().len(),
        cpu_name: cpu.name().to_string(),
        cpu_freqz: cpu.frequency(),
        memory: sys.total_memory(),
    })
}

pub fn systemd_slice(relay: &ResolvedRelayRecord, cpu: usize) -> String {
    let slice_name = format!("tor-{}.slice", relay.name);
    format!(
        "[Unit]\n\
         Description=Systemd slice for Tor relay {name}\n\n\
         [Service]\n\
         Slice={slice}\n\
         CPUAffinity={cpu}\n\
         CPUAccounting=yes\n\
         MemoryAccounting=yes\n",
        name = relay.name,
        slice = slice_name,
        cpu = cpu,
    )
}

/// Find the first private IPv4 address from all network interfaces
pub async fn find_private_ip(handle: &rtnetlink::Handle) -> anyhow::Result<Ipv4Addr> {
    let links = dump_links(handle).await?;

    for (link_index, _) in links {
        let addresses = dump_addresses(handle, link_index).await?;

        for addr in addresses {
            if let IpAddr::V4(ipv4) = addr {
                // Check if it's a private IP address
                if ipv4.is_private() {
                    return Ok(ipv4);
                }
            }
        }
    }

    anyhow::bail!("No private IPv4 address found")
}

/// Rewrite MetricsPort directive to use the specified IP address with port calculated from public IP's last octet
pub fn rewrite_metrics_port(
    relay: &mut patela_server::db::ResolvedRelayRecord,
    metrics_ip: &Ipv4Addr,
) -> anyhow::Result<()> {
    if let Some(_metrics_ports) = relay.resolved_tor_conf.directives.get("MetricsPort") {
        // Extract last octet from public IPv4 address
        let public_ip: Ipv4Addr = relay.ip_v4.parse()?;
        let octets = public_ip.octets();
        let last_octet = octets[3] as u16;

        // Calculate port: 10000 + last octet
        let metrics_port = 10000 + last_octet;

        // Rewrite MetricsPort to private_ip:calculated_port
        let rewritten_ports = vec![TorValue::String(format!("{}:{}", metrics_ip, metrics_port))];

        relay
            .resolved_tor_conf
            .directives
            .insert("MetricsPort".to_string(), rewritten_ports);
    }

    Ok(())
}

/// Generate torrc from ResolvedRelayRecord
pub fn generate_torrc(relay: &patela_server::db::ResolvedRelayRecord) -> anyhow::Result<String> {
    use std::collections::BTreeMap;

    // Convert TorConfig to torrc format
    let tor_conf = &relay.resolved_tor_conf;
    let mut torrc_lines = Vec::new();

    // Sort directives alphabetically for consistent output
    let sorted_directives: BTreeMap<_, _> = tor_conf.directives.iter().collect();

    // Add all directives from resolved configuration
    for (key, values) in sorted_directives {
        for value in values {
            torrc_lines.push(format!("{} {}", key, value));
        }
    }

    Ok(torrc_lines.join("\n"))
}

// Find network interface by the name
pub async fn find_network_interface_by_name(
    handle: &rtnetlink::Handle,
    target: &String,
) -> anyhow::Result<u32> {
    let mut links = handle
        .link()
        .get()
        .set_filter_mask(AddressFamily::Inet, vec![LinkExtentMask::Brvlan])
        .execute();

    while let Some(msg) = links.try_next().await? {
        for nla in msg.attributes.into_iter() {
            match nla {
                LinkAttribute::IfName(name) => {
                    if name.eq(target) {
                        return Ok(msg.header.index);
                    }
                }
                _ => continue,
            }
        }
    }

    anyhow::bail!("No network interface {}", target)
}

// Find the first ethernet interface without an ip
pub async fn find_network_interface(handle: &rtnetlink::Handle) -> anyhow::Result<u32> {
    let mut links = handle
        .link()
        .get()
        .set_filter_mask(AddressFamily::Inet, vec![LinkExtentMask::Brvlan])
        .execute();

    // BTreeMap are always ordered by key
    let mut interfaces: BTreeMap<u32, String> = BTreeMap::new();

    while let Some(msg) = links.try_next().await? {
        for nla in msg.attributes.into_iter() {
            match nla {
                LinkAttribute::IfName(name) => {
                    //println!("Found interface {} with name {:?})", msg.header.index, name);

                    // eth, eno, ens, enp, enx
                    if name.starts_with("e") {
                        interfaces.insert(msg.header.index, name);
                    }
                }
                _ => continue,
            }
        }
    }

    let mut links = handle.address().get().execute();

    while let Some(msg) = links.try_next().await? {
        for nla in msg.attributes.into_iter() {
            match nla {
                AddressAttribute::Address(addr) => {
                    //println!("Found addr {} for index {}", addr, msg.header.index);

                    // remove from hashmap if there is an index, only on if ipv6
                    if addr.is_ipv4() {
                        interfaces.remove(&msg.header.index);
                    }
                }
                _ => continue,
            }
        }
    }

    if let Some(entry) = interfaces.first_entry() {
        return Ok(*entry.key());
    }

    anyhow::bail!("Impossible to find a valid network interface")
}

pub async fn add_default_route_v4(
    gateway: Ipv4Addr,
    handle: &rtnetlink::Handle,
) -> anyhow::Result<()> {
    // delete default route if exist
    let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut routes = handle.route().get(route).execute();

    while let Some(route) = routes.try_next().await? {
        if route.header.destination_prefix_length == 0 {
            println!("Found default route: {:?}", route);
            handle.route().del(route).execute().await?;
        }
    }

    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .gateway(gateway)
        .build();

    handle.route().add(route).execute().await?;

    Ok(())
}

pub async fn add_default_route_v6(
    gateway: Ipv6Addr,
    handle: &rtnetlink::Handle,
) -> anyhow::Result<()> {
    // delete default route if exist
    let route = RouteMessageBuilder::<Ipv6Addr>::new().build();
    let mut routes = handle.route().get(route).execute();

    while let Some(route) = routes.try_next().await? {
        if route.header.destination_prefix_length == 0 {
            println!("Found default route: {:?}", route);
            handle.route().del(route).execute().await?;
        }
    }

    // add default ipv4 route
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .gateway(gateway)
        .build();

    handle.route().add(route).execute().await?;

    Ok(())
}

/// Get all network link
pub async fn dump_links(handle: &rtnetlink::Handle) -> anyhow::Result<Vec<(u32, String)>> {
    let mut links = handle
        .link()
        .get()
        .set_filter_mask(AddressFamily::Inet, vec![LinkExtentMask::Brvlan])
        .execute();

    let mut dump: Vec<(u32, String)> = Vec::new();

    'outer: while let Some(msg) = links.try_next().await? {
        for nla in msg.attributes.into_iter() {
            if let LinkAttribute::IfName(name) = nla {
                println!("found link {} ({})", msg.header.index, name);
                dump.push((msg.header.index, name));
                continue 'outer;
            }
        }
        eprintln!("found link {}, but the link has no name", msg.header.index);
    }

    Ok(dump)
}

/// Get all network addresses for a link
pub async fn dump_addresses(
    handle: &rtnetlink::Handle,
    link_index: u32,
) -> anyhow::Result<Vec<IpAddr>> {
    let mut address_stream = handle
        .address()
        .get()
        .set_link_index_filter(link_index)
        .execute();

    let mut addresses: Vec<IpAddr> = Vec::new();

    while let Some(msg) = address_stream.try_next().await? {
        for nla in msg.attributes.iter() {
            if let AddressAttribute::Address(addr) = nla {
                addresses.push(*addr);
            }
        }
    }

    Ok(addresses)
}

pub async fn add_network_address(
    link_index: u32,
    ip: IpNetwork,
    handle: &rtnetlink::Handle,
) -> anyhow::Result<()> {
    let mut links = handle.link().get().match_index(link_index).execute();

    if let Some(link) = links.try_next().await? {
        handle
            .address()
            .add(link.header.index, ip.ip(), ip.prefix())
            .execute()
            .await?
    }
    Ok(())
}

pub async fn set_link_up(handle: &rtnetlink::Handle, link_index: u32) -> anyhow::Result<()> {
    let mut links = handle.link().get().match_index(link_index).execute();

    if let Some(link) = links.try_next().await? {
        handle
            .link()
            .set(LinkUnspec::new_with_index(link.header.index).up().build())
            .execute()
            .await?
    }

    Ok(())
}

/// This is quite convoluted function because nft is not so easy to understand at a first touch,
/// but the idea is to set the source ip by a mark setted with the process id.
///
/// The iptables equivalents rules are:
///
/// `-A OUTPUT -m owner --uid-owner <user id> -j MARK --set-mark <mark id>`
/// `-A <network interface> -m mark --mark <mark id>/0xff -j SNAT --to-source <source ip>`
///
/// Traslated to nftables:
/// `add rule ip filter OUTPUT skuid <process id> counter meta mark set <mark id>`
/// `add rule ip filter <interface> mark and 0xff == <mark id> counter snat to <source ip>`
pub fn set_source_ip_by_process(
    iface_index: u32,
    pid: u32,
    srcmark: i32,
    ip4: Ipv4Addr,
    ip6: Ipv6Addr,
) -> anyhow::Result<()> {
    // Heavily inspired by https://github.com/mullvad/mullvadvpn-app/blob/5025db74b34cfb3536c43f89f3407ffc0d97ae73/talpid-core/src/firewall/linux.rs#L314
    //
    //// Create a batch. This is used to store all the netlink messages we will later send.
    //// Creating a new batch also automatically writes the initial batch begin message needed
    //// to tell netlink this is a single transaction that might arrive over multiple netlink packets.
    let mut batch = Batch::new();
    //
    //// Create a netfilter table operating on both IPv4 and IPv6 (ProtoFamily::Inet)
    let table = Table::new(NFT_TABLE_NAME, ProtoFamily::Inet);

    //// Add the table to the batch with the `MsgType::Add` type, thus instructing netfilter to add
    //// this table under its `ProtoFamily::Inet` ruleset.
    batch.add(&table, nftnl::MsgType::Add);

    let mut mangle_chain = Chain::new(MANGLE_CHAIN_NAME, &table);

    mangle_chain.set_hook(nftnl::Hook::Out, MANGLE_CHAIN_PRIORITY);
    mangle_chain.set_type(nftnl::ChainType::Route);
    mangle_chain.set_policy(nftnl::Policy::Accept);
    batch.add(&mangle_chain, nftnl::MsgType::Add);

    let mut nat_chain = Chain::new(NAT_CHAIN_NAME, &table);
    nat_chain.set_hook(nftnl::Hook::PostRouting, libc::NF_IP_PRI_NAT_SRC);
    nat_chain.set_type(nftnl::ChainType::Nat);
    nat_chain.set_policy(nftnl::Policy::Accept);
    batch.add(&nat_chain, nftnl::MsgType::Add);

    let mut rule = Rule::new(&mangle_chain);

    // - `add rule ip filter OUTPUT skuid <process id> counter meta mark set <mark id>`
    // load pid
    rule.add_expr(&nft_expr!(meta skuid));
    // check for our pid
    rule.add_expr(&nft_expr!(cmp == pid));
    // Loads `fwmark` into first nftnl register
    rule.add_expr(&nft_expr!(immediate data srcmark));
    // Sets `fwmark` as metadata mark for packet
    rule.add_expr(&nft_expr!(meta mark set));

    batch.add(&rule, nftnl::MsgType::Add);

    // - `add rule ip filter <interface> mark and 0xff == <mark id> counter snat to <source ip>`
    let mut rule = Rule::new(&nat_chain);

    rule.add_expr(&nft_expr!(meta oif));
    rule.add_expr(&nft_expr!(cmp != iface_index));

    rule.add_expr(&nft_expr!(ct mark));
    rule.add_expr(&nft_expr!(cmp == srcmark));

    rule.add_expr(&Immediate::new(ip4, Register::Reg1));

    let nat_expr = Nat {
        nat_type: NatType::SNat,
        family: ProtoFamily::Ipv4,
        ip_register: Register::Reg1,
        port_register: None,
    };
    rule.add_expr(&nat_expr);

    batch.add(&rule, nftnl::MsgType::Add);

    // do the same for ipv6
    let mut rule = Rule::new(&nat_chain);

    rule.add_expr(&nft_expr!(meta oif));
    rule.add_expr(&nft_expr!(cmp != iface_index));

    rule.add_expr(&nft_expr!(ct mark));
    rule.add_expr(&nft_expr!(cmp == srcmark));

    rule.add_expr(&Immediate::new(ip6, Register::Reg1));

    let nat_expr = Nat {
        nat_type: NatType::SNat,
        family: ProtoFamily::Ipv6,
        ip_register: Register::Reg1,
        port_register: None,
    };
    rule.add_expr(&nat_expr);

    batch.add(&rule, nftnl::MsgType::Add);

    let finalized_batch = batch.finalize();

    send_and_process(&finalized_batch)?;

    Ok(())
}

fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> anyhow::Result<Option<&'a [u8]>> {
    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

fn send_and_process(batch: &FinalizedBatch) -> anyhow::Result<()> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    socket.send_all(batch)?;

    let portid = socket.portid();
    let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];
    let netlink_sequence_number = 0; // Sequence number for netlink messages (can be 0)
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, netlink_sequence_number, portid)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Encode, Decode, Default)]
pub enum Ed25519KeyType {
    /// ed25519v1-secret: type0 — the relay master identity key
    #[default]
    Type0 = 0,
    /// ed25519v1-secret: fmly-id — the family identity key
    FamilyId = 1,
}

impl Ed25519KeyType {
    pub fn header(&self) -> &'static [u8] {
        match self {
            Ed25519KeyType::Type0 => TOR_ED25519_HEADER,
            Ed25519KeyType::FamilyId => TOR_FAMILY_KEY_HEADER,
        }
    }

    pub fn from_header(header: &[u8]) -> anyhow::Result<Self> {
        if header == TOR_ED25519_HEADER {
            Ok(Ed25519KeyType::Type0)
        } else if header == TOR_FAMILY_KEY_HEADER {
            Ok(Ed25519KeyType::FamilyId)
        } else {
            anyhow::bail!("Unknown ed25519 key header")
        }
    }
}

#[derive(Debug, Encode, Decode)]
pub struct RelayKeyData {
    pub t: Ed25519KeyType,
    pub i: usize,
    pub ed: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
}

fn strip_ed25519_header(key_file_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    strip_ed25519_key(key_file_data, TOR_ED25519_HEADER)
}

fn strip_family_key_header(key_file_data: &[u8]) -> anyhow::Result<Vec<u8>> {
    strip_ed25519_key(key_file_data, TOR_FAMILY_KEY_HEADER)
}

fn strip_ed25519_key(key_file_data: &[u8], expected_header: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        key_file_data.len() == 96,
        "Expected 96 bytes, got {}",
        key_file_data.len()
    );
    anyhow::ensure!(
        &key_file_data[..32] == expected_header,
        "Invalid ed25519 key header"
    );
    Ok(key_file_data[32..].to_vec())
}

fn add_ed25519_header(key_data: &[u8], key_type: &Ed25519KeyType) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        key_data.len() == 64,
        "Expected 64 bytes of key data, got {}",
        key_data.len()
    );
    let mut result = Vec::with_capacity(96);
    result.extend_from_slice(key_type.header());
    result.extend_from_slice(key_data);
    Ok(result)
}

fn rsa_pem_to_primes(data: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let pem = pem::parse(data).context("Failed to parse PEM file")?;

    let rsa_key = rsa::RsaPrivateKey::from_pkcs1_der(pem.contents())
        .context("Failed to parse RSA key from DER")?;
    let rsa_primes = rsa_key.primes();

    let p = rsa_primes[0].to_bytes_be();
    let q = rsa_primes[1].to_bytes_be();
    Ok((p, q))
}

// TOR RSA PEM format:
// - base64 encoded DER
// - 64 characters lines
// - enclosed by RSA key header and footer
fn tor_format_rsa_key(key: &rsa::RsaPrivateKey) -> String {
    let der = key.to_pkcs1_der().unwrap();
    let pem = Pem::new("RSA PRIVATE KEY", der.as_bytes());
    let config = EncodeConfig::new()
        .set_line_wrap(64)
        .set_line_ending(pem::LineEnding::LF);
    encode_config(&pem, config)
}

fn rsa_primes_to_pem(p: &[u8], q: &[u8]) -> anyhow::Result<String> {
    let p = BigUint::from_bytes_be(p);
    let q = BigUint::from_bytes_be(q);
    let rsa_key =
        rsa::RsaPrivateKey::from_primes(vec![p, q], BigUint::from_bytes_be(TOR_RSA_EXPONENT))?;
    let pem = tor_format_rsa_key(&rsa_key);
    Ok(pem)
}

pub fn serialize_relay_keys(relays: &[ResolvedRelayRecord]) -> anyhow::Result<Vec<u8>> {
    let mut relay_keys = Vec::new();

    // Backup the family key from the first relay's keys dir (shared across all relays)
    if let Some(first_relay) = relays.first() {
        let keys_dir = Path::new(&TOR_INSTANCE_LIB_DIR)
            .join(&first_relay.name)
            .join("keys");
        let family_key_path = keys_dir.join(TOR_FAMILY_KEY_NAME);
        if family_key_path.exists() {
            let family_key_data = fs::read(&family_key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read family key: {}", e))?;
            relay_keys.push(RelayKeyData {
                i: usize::MAX,
                ed: strip_family_key_header(&family_key_data)?,
                p: Vec::new(),
                q: Vec::new(),
                t: Ed25519KeyType::FamilyId,
            });
            println!("Backed up family key");
        }
    }

    for relay in relays {
        let keys_dir = Path::new(&TOR_INSTANCE_LIB_DIR)
            .join(&relay.name)
            .join("keys");

        let key_path = keys_dir.join(TOR_MASTER_KEY_NAME);
        let key_data = fs::read(&key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read key for relay {}: {}", relay.name, e))?;

        let rsa_path = keys_dir.join(TOR_RSA_KEY_NAME);
        let rsa_data = fs::read(&rsa_path).map_err(|e| {
            anyhow::anyhow!("Failed to read RSA key for relay {}: {}", relay.name, e)
        })?;
        let (p, q) = rsa_pem_to_primes(&rsa_data)?;

        relay_keys.push(RelayKeyData {
            i: relay.id as usize, // :)
            ed: strip_ed25519_header(&key_data)?,
            p,
            q,
            t: Ed25519KeyType::Type0,
        });
        println!("Backed up relay: {}", relay.name);
    }
    let bytes = bincode::encode_to_vec(&relay_keys, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Failed to serialize backup with bincode: {}", e))?;

    Ok(bytes)
}

pub fn deserialize_relay_keys(data: &[u8]) -> anyhow::Result<Vec<RelayKeyData>> {
    let trimmed = data
        .iter()
        .rposition(|&b| b != 0)
        .map(|pos| &data[..=pos])
        .unwrap_or(data);

    let (backup, _): (Vec<RelayKeyData>, usize) =
        bincode::decode_from_slice(trimmed, bincode::config::standard()).map_err(|e| {
            anyhow::anyhow!("Failed to deserialize backup data with bincode, {}", e)
        })?;
    Ok(backup)
}

pub fn backup_tor_keys_to_tpm(
    ctx: &mut TpmContext,
    nv_handle: NvIndexHandle,
    nv_size: usize,
    relays: &[ResolvedRelayRecord],
) -> anyhow::Result<()> {
    println!("Backing up Tor relay keys to TPM...");

    let serialized = serialize_relay_keys(relays)?;
    // Pad data to nv_size
    let mut padded_data = serialized;
    padded_data.resize(nv_size, 0);

    nv_write_data(ctx, nv_handle, &padded_data)?;

    println!("Successfully backed up {} relay keys to TPM", relays.len());
    Ok(())
}

pub fn restore_tor_keys_from_tpm(
    ctx: &mut TpmContext,
    nv_handle: NvIndexHandle,
    _nv_size: usize,
    relays: &[ResolvedRelayRecord],
) -> anyhow::Result<()> {
    println!("Restoring Tor relay keys from TPM");

    let data = nv_read_data(ctx, nv_handle)?;
    let restored_keys = deserialize_relay_keys(&data)?;

    // Restore family key to all relay key dirs
    let family_key = restored_keys
        .iter()
        .find(|rk| rk.t == Ed25519KeyType::FamilyId);

    for relay in relays {
        let (key_data, rsa_data) = restored_keys
            .iter()
            .find(|rk| rk.i == (relay.id as usize) && rk.t == Ed25519KeyType::Type0)
            .ok_or_else(|| anyhow::anyhow!("No backup found for relay {}", relay.name))
            .and_then(|rk| {
                Ok((
                    add_ed25519_header(&rk.ed, &rk.t)?,
                    rsa_primes_to_pem(&rk.p, &rk.q)?,
                ))
            })?;

        let keys_dir = Path::new(&TOR_INSTANCE_LIB_DIR)
            .join(&relay.name)
            .join("keys");

        fs::create_dir_all(&keys_dir)?;

        let rsa_path = keys_dir.join(TOR_RSA_KEY_NAME);
        fs::write(&rsa_path, rsa_data).map_err(|e| {
            anyhow::anyhow!("Failed to write RSA key for relay {}: {}", relay.name, e)
        })?;

        let key_path = keys_dir.join(TOR_MASTER_KEY_NAME);
        fs::write(&key_path, key_data)
            .map_err(|e| anyhow::anyhow!("Failed to write key for relay {}: {}", relay.name, e))?;

        if let Some(fk) = family_key {
            let family_key_data = add_ed25519_header(&fk.ed, &Ed25519KeyType::FamilyId)?;
            let family_key_path = keys_dir.join(TOR_FAMILY_KEY_NAME);
            fs::write(&family_key_path, family_key_data).map_err(|e| {
                anyhow::anyhow!("Failed to write family key for relay {}: {}", relay.name, e)
            })?;
        }

        let uid = Passwd::from_name(CString::new(format!("_tor-{}", &relay.name))?)?
            .ok_or_else(|| anyhow::anyhow!("User _tor-{} not found", relay.name))?
            .uid;
        let gid = Passwd::from_name(CString::new(format!("_tor-{}", &relay.name))?)?
            .ok_or_else(|| anyhow::anyhow!("Group _tor-{} not found", relay.name))?
            .gid;

        chown(&keys_dir, Some(uid), Some(gid))?;

        for entry in fs::read_dir(&keys_dir)? {
            chown(entry?.path(), Some(uid), Some(gid))?;
        }

        println!("Restored key for relay: {}", relay.name);
    }

    println!("Successfully restored {} relay keys from TPM", relays.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::LineEnding;
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};

    #[test]
    fn test_strip_ed25519_header() {
        // Create a valid 96-byte key with header
        let mut key_data = Vec::new();
        key_data.extend_from_slice(TOR_ED25519_HEADER);
        key_data.extend_from_slice(&[0u8; 64]); // 64 bytes of key data

        let result = strip_ed25519_header(&key_data).unwrap();

        assert_eq!(result.len(), 64);
        assert_eq!(result, vec![0u8; 64]);
    }

    #[test]
    fn test_strip_ed25519_header_invalid_length() {
        let key_data = vec![0u8; 50]; // Wrong length
        let result = strip_ed25519_header(&key_data);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected 96 bytes")
        );
    }

    #[test]
    fn test_strip_ed25519_header_invalid_header() {
        let key_data = vec![0u8; 96];
        // Wrong header (not matching TOR_ED25519_HEADER)

        let result = strip_ed25519_header(&key_data);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid ed25519 key header")
        );
    }

    #[test]
    fn test_add_ed25519_header() {
        let key_data = vec![0xAB; 64];

        let result = add_ed25519_header(&key_data, &Ed25519KeyType::Type0).unwrap();

        assert_eq!(result.len(), 96);
        assert_eq!(&result[..32], TOR_ED25519_HEADER);
        assert_eq!(&result[32..], &key_data[..]);
    }

    #[test]
    fn test_add_ed25519_header_invalid_length() {
        let key_data = vec![0u8; 50]; // Wrong length

        let result = add_ed25519_header(&key_data, &Ed25519KeyType::Type0);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Expected 64 bytes")
        );
    }

    #[test]
    fn test_ed25519_header_roundtrip() {
        // Create original key with header
        let mut original = Vec::new();
        original.extend_from_slice(TOR_ED25519_HEADER);
        original.extend_from_slice(&[0xAB; 64]);

        // Strip header
        let stripped = strip_ed25519_header(&original).unwrap();

        // Add header back
        let restored = add_ed25519_header(&stripped, &Ed25519KeyType::Type0).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_rsa_pem_to_primes() {
        let mut rng = rand::thread_rng();
        let e_bigint = BigUint::from_bytes_be(TOR_RSA_EXPONENT);
        let key = RsaPrivateKey::new_with_exp(&mut rng, 1024, &e_bigint).unwrap();
        let pem = key.to_pkcs1_pem(LineEnding::LF).unwrap();

        let (p, q) = rsa_pem_to_primes(pem.as_bytes()).unwrap();

        // Check sizes are reasonable for 1024-bit RSA
        assert!(p.len() >= 60 && p.len() <= 68, "p size: {}", p.len());
        assert!(q.len() >= 60 && q.len() <= 68, "q size: {}", q.len());

        // Verify we can reconstruct the key
        let p_bigint = BigUint::from_bytes_be(&p);
        let q_bigint = BigUint::from_bytes_be(&q);
        let e_bigint = BigUint::from_bytes_be(TOR_RSA_EXPONENT);

        let reconstructed = RsaPrivateKey::from_primes(vec![p_bigint, q_bigint], e_bigint).unwrap();

        // Original and reconstructed should have same modulus
        assert_eq!(key.n(), reconstructed.n());
    }

    #[test]
    fn test_rsa_primes_to_pem() {
        let mut rng = rand::thread_rng();
        let e_bigint = BigUint::from_bytes_be(TOR_RSA_EXPONENT);
        let key = RsaPrivateKey::new_with_exp(&mut rng, 1024, &e_bigint).unwrap();

        let primes = key.primes();
        let p = primes[0].to_bytes_be();
        let q = primes[1].to_bytes_be();

        let pem = rsa_primes_to_pem(&p, &q).unwrap();

        // Check it's valid PEM format
        assert!(pem.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(pem.ends_with("-----END RSA PRIVATE KEY-----\n"));

        // Verify we can parse it back
        let reconstructed = RsaPrivateKey::from_pkcs1_pem(&pem).unwrap();
        assert_eq!(key.n(), reconstructed.n());
    }

    #[test]
    fn test_rsa_roundtrip() {
        let mut rng = rand::thread_rng();
        let e_bigint = BigUint::from_bytes_be(TOR_RSA_EXPONENT);
        let original_key = RsaPrivateKey::new_with_exp(&mut rng, 1024, &e_bigint).unwrap();
        let original_pem = original_key.to_pkcs1_pem(LineEnding::LF).unwrap();

        // Convert to primes
        let (p, q) = rsa_pem_to_primes(original_pem.as_bytes()).unwrap();

        // Convert back to PEM
        let restored_pem = rsa_primes_to_pem(&p, &q).unwrap();

        // Parse both and compare modulus
        let original = RsaPrivateKey::from_pkcs1_pem(&original_pem).unwrap();
        let restored = RsaPrivateKey::from_pkcs1_pem(&restored_pem).unwrap();

        assert_eq!(original.n(), restored.n());
    }

    #[test]
    fn test_relay_key_data_serialization() {
        let relay_data = RelayKeyData {
            i: 42,
            ed: vec![0xAB; 64],
            p: vec![0xCD; 64],
            q: vec![0xEF; 64],
            t: Ed25519KeyType::Type0,
        };

        let serialized = bincode::encode_to_vec(&relay_data, bincode::config::standard()).unwrap();

        // Should be reasonably compact
        assert!(
            serialized.len() < 250,
            "Serialized size: {}",
            serialized.len()
        );

        let (deserialized, _): (RelayKeyData, usize) =
            bincode::decode_from_slice(&serialized, bincode::config::standard()).unwrap();

        assert_eq!(deserialized.i, relay_data.i);
        assert_eq!(deserialized.ed, relay_data.ed);
        assert_eq!(deserialized.p, relay_data.p);
        assert_eq!(deserialized.q, relay_data.q);
    }

    #[test]
    fn test_deserialize_relay_keys_with_padding() {
        let relay_data = RelayKeyData {
            i: 1,
            ed: vec![0x11; 64],
            p: vec![0x22; 64],
            q: vec![0x33; 64],
            t: Ed25519KeyType::FamilyId,
        };

        let mut serialized =
            bincode::encode_to_vec(vec![relay_data], bincode::config::standard()).unwrap();

        // Add padding
        serialized.resize(2048, 0);

        // Should still deserialize correctly
        let deserialized = deserialize_relay_keys(&serialized).unwrap();

        assert_eq!(deserialized.len(), 1);
        assert_eq!(deserialized[0].i, 1);
        assert_eq!(deserialized[0].ed, vec![0x11; 64]);
        assert_eq!(deserialized[0].t, Ed25519KeyType::FamilyId);
    }

    #[test]
    fn test_deserialize_relay_keys_with_family_and_type0() {
        let family_key = RelayKeyData {
            i: usize::MAX,
            ed: vec![0xFF; 64],
            p: Vec::new(),
            q: Vec::new(),
            t: Ed25519KeyType::FamilyId,
        };

        let relay_data = RelayKeyData {
            i: 1,
            ed: vec![0x11; 64],
            p: vec![0x22; 64],
            q: vec![0x33; 64],
            t: Ed25519KeyType::Type0,
        };

        let serialized =
            bincode::encode_to_vec(vec![family_key, relay_data], bincode::config::standard())
                .unwrap();

        let deserialized = deserialize_relay_keys(&serialized).unwrap();

        assert_eq!(deserialized.len(), 2);

        // Family key entry
        assert_eq!(deserialized[0].i, usize::MAX);
        assert_eq!(deserialized[0].t, Ed25519KeyType::FamilyId);
        assert_eq!(deserialized[0].ed, vec![0xFF; 64]);
        assert!(deserialized[0].p.is_empty());
        assert!(deserialized[0].q.is_empty());

        // Relay key entry
        assert_eq!(deserialized[1].i, 1);
        assert_eq!(deserialized[1].t, Ed25519KeyType::Type0);
        assert_eq!(deserialized[1].ed, vec![0x11; 64]);
    }

    #[test]
    fn test_deserialize_relay_keys_multiple() {
        let relay_data1 = RelayKeyData {
            i: 1,
            ed: vec![0x11; 64],
            p: vec![0x22; 64],
            q: vec![0x33; 64],
            t: Ed25519KeyType::FamilyId,
        };

        let relay_data2 = RelayKeyData {
            i: 2,
            ed: vec![0xAA; 64],
            p: vec![0xBB; 64],
            q: vec![0xCC; 64],
            t: Ed25519KeyType::FamilyId,
        };

        let serialized =
            bincode::encode_to_vec(vec![relay_data1, relay_data2], bincode::config::standard())
                .unwrap();

        let deserialized = deserialize_relay_keys(&serialized).unwrap();

        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0].i, 1);
        assert_eq!(deserialized[1].i, 2);
        assert_eq!(deserialized[0].ed, vec![0x11; 64]);
        assert_eq!(deserialized[1].ed, vec![0xAA; 64]);
    }

    #[test]
    fn test_deserialize_empty_data() {
        let data = vec![0u8; 100];

        let deserialized = deserialize_relay_keys(&data).unwrap();
        assert!(deserialized.is_empty());
    }

    #[test]
    fn test_serialization_size_estimate() {
        // Test with realistic 1024-bit RSA components
        let mut rng = rand::thread_rng();
        let e_bigint = BigUint::from_bytes_be(TOR_RSA_EXPONENT);
        let key = RsaPrivateKey::new_with_exp(&mut rng, 1024, &e_bigint).unwrap();
        let primes = key.primes();

        let relay_data = RelayKeyData {
            i: 1,
            ed: vec![0xAB; 64],
            p: primes[0].to_bytes_be(),
            q: primes[1].to_bytes_be(),
            t: Ed25519KeyType::Type0,
        };

        let serialized = bincode::encode_to_vec(&relay_data, bincode::config::standard()).unwrap();

        println!("Single relay serialized size: {} bytes", serialized.len());

        // Should be around 210-220 bytes
        assert!(
            serialized.len() < 250,
            "Size too large: {}",
            serialized.len()
        );
        assert!(
            serialized.len() > 180,
            "Size suspiciously small: {}",
            serialized.len()
        );

        // Test 10 relays
        let four_relays = vec![&relay_data; 10];
        let serialized_four =
            bincode::encode_to_vec(&four_relays, bincode::config::standard()).unwrap();

        println!(
            "Ten relays serialized size: {} bytes",
            serialized_four.len()
        );

        // Should fit in 1 NV index (2048 bytes)
        assert!(
            serialized_four.len() < 2048,
            "Ten relays too large: {}",
            serialized_four.len()
        );
    }

    #[test]
    fn test_family_key_header_roundtrip() {
        let mut original = Vec::new();
        original.extend_from_slice(TOR_FAMILY_KEY_HEADER);
        original.extend_from_slice(&[0xAB; 64]);

        let stripped = strip_family_key_header(&original).unwrap();
        let restored = add_ed25519_header(&stripped, &Ed25519KeyType::FamilyId).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_ed25519_key_type_from_header() {
        assert_eq!(
            Ed25519KeyType::from_header(TOR_ED25519_HEADER).unwrap(),
            Ed25519KeyType::Type0
        );
        assert_eq!(
            Ed25519KeyType::from_header(TOR_FAMILY_KEY_HEADER).unwrap(),
            Ed25519KeyType::FamilyId
        );
        assert!(
            Ed25519KeyType::from_header(b"invalid header padding here!!!\x00\x00\x00").is_err()
        );
    }
}
