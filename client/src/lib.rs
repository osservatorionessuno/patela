include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use crate::tpm::*;
use etc_passwd::Passwd;
use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use nftnl::{
    Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
    expr::{Immediate, Nat, NatType, Register},
    nft_expr,
    nftnl_sys::libc,
};
use patela_server::{HwSpecs, db::ResolvedRelayRecord};
use rtnetlink::{
    LinkUnspec, RouteMessageBuilder,
    packet_route::{
        AddressFamily,
        address::AddressAttribute,
        link::{LinkAttribute, LinkExtentMask},
    },
};
use serde::{Deserialize, Serialize};
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

pub fn collect_specs() -> anyhow::Result<HwSpecs> {
    let sys = System::new_all();
    let cpu = sys.cpus().first().unwrap();

    Ok(HwSpecs {
        n_cpus: sys.cpus().len(),
        cpu_name: cpu.name().to_string(),
        cpu_freqz: cpu.frequency(),
        memory: sys.total_memory(),
    })
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
    let table = Table::new(&NFT_TABLE_NAME, ProtoFamily::Inet);

    //// Add the table to the batch with the `MsgType::Add` type, thus instructing netfilter to add
    //// this table under its `ProtoFamily::Inet` ruleset.
    batch.add(&table, nftnl::MsgType::Add);

    let mut mangle_chain = Chain::new(&MANGLE_CHAIN_NAME, &table);

    mangle_chain.set_hook(nftnl::Hook::Out, MANGLE_CHAIN_PRIORITY);
    mangle_chain.set_type(nftnl::ChainType::Route);
    mangle_chain.set_policy(nftnl::Policy::Accept);
    batch.add(&mangle_chain, nftnl::MsgType::Add);

    let mut nat_chain = Chain::new(&NAT_CHAIN_NAME, &table);
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayKeyData {
    pub instance_name: String,
    #[serde(with = "serde_bytes")]
    pub ed25519_master_id_secret_key: Vec<u8>,
}

pub fn serialize_relay_keys(relays: &[ResolvedRelayRecord]) -> anyhow::Result<Vec<u8>> {
    let mut relay_keys = Vec::new();

    for relay in relays {
        let keys_dir = Path::new(&TOR_INSTANCE_LIB_DIR)
            .join(&relay.name)
            .join("keys");

        let key_path = keys_dir.join(TOR_MASTER_KEY_NAME);
        let key_data = fs::read(&key_path)
            .map_err(|e| anyhow::anyhow!("Failed to read key for relay {}: {}", relay.name, e))?;

        relay_keys.push(RelayKeyData {
            instance_name: relay.name.clone(),
            ed25519_master_id_secret_key: key_data,
        });
    }
    let json = serde_json::to_string(&relay_keys)
        .map_err(|e| anyhow::anyhow!("Failed to serialize backup to JSON: {}", e))?;

    let bytes = json.into_bytes();

    Ok(bytes)
}

pub fn deserialize_relay_keys(data: &[u8]) -> anyhow::Result<Vec<RelayKeyData>> {
    let trimmed = data
        .iter()
        .rposition(|&b| b != 0)
        .map(|pos| &data[..=pos])
        .unwrap_or(data);

    let json_str = std::str::from_utf8(trimmed)
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in backup data: {}", e))?;

    let backup: Vec<RelayKeyData> = serde_json::from_str(json_str)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize backup data: {}", e))?;

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

    for relay in relays {
        let key_data = restored_keys
            .iter()
            .find(|rk| rk.instance_name == relay.name)
            .map(|rk| rk.ed25519_master_id_secret_key.clone())
            .ok_or_else(|| anyhow::anyhow!("No backup found for relay {}", relay.name))?;

        let keys_dir = Path::new(&TOR_INSTANCE_LIB_DIR)
            .join(&relay.name)
            .join("keys");

        fs::create_dir_all(&keys_dir)?;

        let key_path = keys_dir.join(TOR_MASTER_KEY_NAME);
        fs::write(&key_path, key_data)
            .map_err(|e| anyhow::anyhow!("Failed to write key for relay {}: {}", relay.name, e))?;

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
