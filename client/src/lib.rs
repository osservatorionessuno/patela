include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use netlink_packet_route::{
    AddressFamily,
    address::AddressAttribute,
    link::{LinkAttribute, LinkExtentMask},
};
use nftnl::{
    Batch, Chain, ProtoFamily, Rule, Table,
    expr::{Immediate, Nat, NatType, Register},
    nft_expr,
    nftnl_sys::libc,
};
use patela_server::{HwSpecs, HwSpecsNetwork, Network, TorRelayConf};
use std::{
    collections::BTreeMap,
    ffi::CStr,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
use sysinfo::{Networks, System};
use tar::{Archive, Builder};
use tera::{Context, Tera};

pub mod api;
pub mod tpm;

const NFT_TABLE_NAME: &CStr = c"patela";
const MANGLE_CHAIN_NAME: &CStr = c"mangle";
const MANGLE_CHAIN_PRIORITY: i32 = libc::NF_IP_PRI_MANGLE;
const NAT_CHAIN_NAME: &CStr = c"nat";
const TOR_INSTANCE_LIB_DIR: &'static str = "/var/lib/tor-instances";

lazy_static! {
    static ref TEMPLATES: Tera = {
        let mut tera = Tera::default();
        if let Err(e) = tera.add_raw_template("torrc", TORRC_TEMLPLATE) {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        };

        tera
    };
}

pub fn collect_specs() -> anyhow::Result<HwSpecs> {
    let sys = System::new_all();
    let cpu = sys.cpus().first().unwrap();

    let _networks: Vec<HwSpecsNetwork> = Networks::new_with_refreshed_list()
        .iter()
        .map(|(interface_name, data)| HwSpecsNetwork {
            name: interface_name.to_string(),
            mac_addr: data.mac_address().to_string(),
            address: data
                .ip_networks()
                .to_vec()
                .iter()
                .map(|n| Network {
                    addr: n.addr.to_string(),
                    prefix: n.prefix,
                })
                .collect(),
        })
        .collect();

    Ok(HwSpecs {
        n_cpus: sys.cpus().len(),
        cpu_name: cpu.name().to_string(),
        cpu_freqz: cpu.frequency(),
        memory: sys.total_memory(),
        //network: networks,
    })
}

pub fn generate_torrc(conf: &TorRelayConf) -> anyhow::Result<String> {
    TEMPLATES
        .render("torrc", &Context::from_serialize(&conf)?)
        .map_err(anyhow::Error::from)
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
                    println!("Found interface {} with name {:?})", msg.header.index, name);

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
                    println!("Found addr {} for index {}", addr, msg.header.index);

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

/// This is quite convoluted function because nft is not so easy to understand at a first touch,
/// but the idea is to set the source ip by a mark setted with the process id.
///
/// The iptables equivalents rules are:
///
///     - `-A OUTPUT -m owner --uid-owner <process id> -j MARK --set-mark <mark id>`
///     - `-A <network interface> -m mark --mark <mark id>/0xff -j SNAT --to-source <source ip>`
///
/// Traslated to nftables:
///     - `add rule ip filter OUTPUT skuid <process id> counter meta mark set <mark id>`
///     - `add rule ip filter <interface> mark and 0xff == <mark id> counter snat to <source ip>`
pub fn set_source_ip_by_process(
    iface_index: u32,
    pid: u32,
    ip4: Ipv4Addr,
    _ip6: Ipv6Addr,
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
    //
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

    let srcmark = 0x101;

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

    // TODO: add ipv6
    Ok(())
}

/// Create an in-memory tar archive, because the content are crypt keys is not very useful to
/// compress the archive, but maybe in future could be interesting. The reason for archive is just
/// for easy storing/encrypt/decrypt as a single blob
pub fn backup_tor_keys(name: &str) -> anyhow::Result<Vec<u8>> {
    let mut archive = Builder::new(Vec::new());

    archive.append_path(Path::new(&TOR_INSTANCE_LIB_DIR).join(name).join("keys/"))?;

    Ok(archive.into_inner()?)
}

/// Unarchive tor keys in a tor instance directory, make sure that the directory exist
pub fn restore_tor_keys(name: &str, data: &[u8]) -> anyhow::Result<()> {
    let mut archive = Archive::new(data);
    archive
        .unpack(Path::new(&TOR_INSTANCE_LIB_DIR).join(name).join("keys/"))
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use patela_server::{TorPolicy, TorPolicyVerb};

    use super::*;

    const TORRC_EXAMPLE: &'static str = "
Nickname miaomiao

ORPort 0.0.0.0:9001
ORPort [0.0.0.0]:9001

RelayBandwidthRate 10 MB
RelayBandwidthBurst 100 MB

ContactInfo email:info[]osservatorionessuno.org url:https://osservatorionessuno.org proof:uri-rsa abuse:exit[]osservatorionessuno.org mastodon:https://mastodon.cisti.org/@0n_odv donationurl:https://osservatorionessuno.org/participate/ ciissversion:2

MyFamily adadadads

ExitPolicy reject 0.0.0.0/8:*
ExitPolicy reject 169.254.0.0/16:*
ExitPolicy reject 10.0.0.0/8:*
ExitPolicy reject *:25
ExitPolicy accept *:*

ExitRelay 1
IPv6Exit 1
";

    #[test]
    fn test_generate_torrc() {
        let tor_conf = TorRelayConf {
            name: String::from("miaomiao"),
            family: String::from("adadadads"),
            or_address_v4: String::from("0.0.0.0"),
            or_address_v6: String::from("0.0.0.0"),
            or_port: 9001,
            bandwidth_rate: 10,
            bandwidth_burst: 100,
            policy: vec![
                TorPolicy {
                    verb: TorPolicyVerb::Reject,
                    object: String::from("0.0.0.0/8:*"),
                },
                TorPolicy {
                    verb: TorPolicyVerb::Reject,
                    object: String::from("169.254.0.0/16:*"),
                },
                TorPolicy {
                    verb: TorPolicyVerb::Reject,
                    object: String::from("10.0.0.0/8:*"),
                },
                TorPolicy {
                    verb: TorPolicyVerb::Reject,
                    object: String::from("*:25"),
                },
                TorPolicy {
                    verb: TorPolicyVerb::Accept,
                    object: String::from("*:*"),
                },
            ],
        };

        let res = generate_torrc(&tor_conf).unwrap();

        println!("{}", res);

        assert_eq!(res, TORRC_EXAMPLE);
    }
}
