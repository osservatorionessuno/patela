include!(concat!(env!("OUT_DIR"), "/const_gen.rs"));

use aes_gcm::{
    AeadCore, Aes256Gcm, AesGcm, KeyInit,
    aead::{
        OsRng,
        consts::{B0, B1},
    },
    aes::{
        Aes256,
        cipher::typenum::{UInt, UTerm},
    },
};
use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use nftnl::{
    Batch, Chain, FinalizedBatch, ProtoFamily, Rule, Table,
    expr::{Immediate, Nat, NatType, Register},
    nft_expr,
    nftnl_sys::libc,
};
use patela_server::{HwSpecs, HwSpecsNetwork, Network, TorRelayConf};
use reqwest::Client;
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
    ffi::CStr,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
use sysinfo::{Networks, System};
use tar::{Archive, Builder};
use tera::Tera;

pub mod api;
pub mod tpm;

const NFT_TABLE_NAME: &CStr = c"patela";
const MANGLE_CHAIN_NAME: &CStr = c"mangle";
const MANGLE_CHAIN_PRIORITY: i32 = libc::NF_IP_PRI_MANGLE;
const NAT_CHAIN_NAME: &CStr = c"nat";
pub const TOR_INSTANCE_LIB_DIR: &'static str = "/var/lib/tor-instances";

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
        .render("torrc", &tera::Context::from_serialize(conf)?)
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
    let very_unclear_what_this_is_for = 0;
    while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
        match mnl::cb_run(message, very_unclear_what_this_is_for, portid)? {
            mnl::CbResult::Stop => {
                break;
            }
            mnl::CbResult::Ok => (),
        }
    }
    Ok(())
}

/// Create an in-memory tar archive, because the content are crypt keys is not very useful to
/// compress the archive, but maybe in future could be interesting. The reason for archive is just
/// for easy storing/encrypt/decrypt as a single blob
pub fn backup_tor_keys(name: &str) -> anyhow::Result<Vec<u8>> {
    let mut archive = Builder::new(Vec::new());

    archive.append_dir_all(
        ".",
        Path::new(&TOR_INSTANCE_LIB_DIR).join(name).join("keys"),
    )?;

    Ok(archive.into_inner()?)
}

/// Unarchive tor keys in a tor instance directory, make sure that the directory exist
pub fn restore_tor_keys(name: &str, data: &[u8]) -> anyhow::Result<()> {
    let mut archive = Archive::new(data);
    archive
        .unpack(Path::new(&TOR_INSTANCE_LIB_DIR).join(name).join("keys/"))
        .map_err(anyhow::Error::from)
}

// Generate aes-gcp key from os random and a one-time nonce that should be renovated each time, the
// key is stored encrypted on the server
pub async fn generate_aes_cipher_and_store(
    tpm_ctx: &mut tss_esapi::Context,
    client: &Client,
    server_url: &str,
    session_token: &str,
) -> anyhow::Result<(
    AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    [u8; 12],
)> {
    // Generate key random
    let key = Aes256Gcm::generate_key(OsRng);

    // The nonce should be used only once and shared
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // encrypt the aes key with tpm
    let ciphered_key = tpm::encrypt(tpm_ctx, key.to_vec());

    let _ = client
        .post(format!("{}/private/node/key", server_url))
        .bearer_auth(session_token)
        .body(ciphered_key)
        .send()
        .await?
        .error_for_status()?;

    let _ = client
        .post(format!("{}/private/node/nonce", server_url))
        .bearer_auth(session_token)
        .body(nonce.to_vec())
        .send()
        .await?
        .error_for_status()?;

    let cipher = Aes256Gcm::new(&key);

    Ok((cipher, nonce.into()))
}

// Fetch aes-gcp key and nonce from server, encrypt with the tpm before storing
pub async fn fetch_aes_key(
    tpm_ctx: &mut tss_esapi::Context,
    client: &Client,
    server_url: &str,
    session_token: &str,
) -> anyhow::Result<(
    AesGcm<Aes256, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>,
    [u8; 12],
)> {
    let ciphered_key = client
        .get(format!("{}/private/node/key", server_url))
        .bearer_auth(session_token)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let nonce: Vec<u8> = client
        .get(format!("{}/private/node/nonce", server_url))
        .bearer_auth(session_token)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?
        .into();

    // decrypt aes key with tpm
    let key = tpm::decrypt(tpm_ctx, ciphered_key.into());

    let cipher = Aes256Gcm::new(key.as_slice().into());

    let nonce_array: [u8; 12] = nonce.as_slice().try_into()?;

    Ok((cipher, nonce_array))
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

MyFamily one two three

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
            family: String::from("one two three"),
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
