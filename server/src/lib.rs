use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{
    cmp, env,
    fmt::{self, Display},
};

pub mod api;
pub mod db;
pub mod tor_config;

const RELAY_MEMORY_BOUND: u64 = 1024; // TODO: configurable
pub const RELAY_OR_PORT: u16 = 9001;

lazy_static! {
    pub static ref GATEWAY_V4: String = env::var("PATELA_GATEWAY_V4").unwrap();
    pub static ref GATEWAY_V6: String = env::var("PATELA_GATEWAY_V6").unwrap();
    pub static ref PREFIX_V4: u8 = env::var("PATELA_PREFIX_V4").unwrap().parse().unwrap();
    pub static ref PREFIX_V6: u8 = env::var("PATELA_PREFIX_V6").unwrap().parse().unwrap();
    pub static ref DNS_SERVER: String = env::var("PATELA_DNS_SERVER").unwrap();
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TorPolicyVerb {
    Accept,
    Reject,
}

/// Tor policy rules are defined for `ip/mask:port`, for simplicity are defined as a simple string
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TorPolicy {
    pub verb: TorPolicyVerb,
    pub object: String,
}

/// Tor configuration, this is just a small small subset of all the possible configuration, but is
/// ok for the use of an exit node
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TorRelayConf {
    pub name: String,
    pub family: String,
    pub policy: Vec<TorPolicy>,
    pub or_address_v4: String,
    pub or_address_v6: String,
    pub or_port: u16,
    pub bandwidth_rate: u16,
    pub bandwidth_burst: u16,
}

impl Display for TorRelayConf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}\t\t{}\t{}",
            self.name, self.or_address_v4, self.or_address_v6
        )
    }
}

/// This is not used now because we assume dhcp server working correctly
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkConf {
    pub ipv4_gateway: String,
    pub ipv4_prefix: u8,
    pub ipv6_gateway: String,
    pub ipv6_prefix: u8,
    pub dns_server: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SystemConf {
    pub ssh_keys: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Network {
    pub addr: String,
    pub prefix: u8,
}

/// Network device
#[derive(Serialize, Deserialize, Debug)]
pub struct HwSpecsNetwork {
    pub name: String,
    pub mac_addr: String,
    pub address: Vec<Network>,
}

/// Hw info
#[derive(Serialize, Deserialize, Debug)]
pub struct HwSpecs {
    pub n_cpus: usize,
    pub cpu_freqz: u64,
    pub cpu_name: String,
    pub memory: u64,
}

// TODO:
// pub fn set_torrc_as_default_conf(input: String) {}
// TODO:
// pub fn get_default_conf(input: String) {}
// TODO:
// pub fn set_torrc_as_node_conf(input: String, node: id) {}
// TODO:
// pub fn get_node_conf(input: String, node: id) {}
// TODO:
// pub fn set_relay_conf(input: String, node: id, name, value) {}
// TODO:
// pub fn get_relay_conf(input: String, node: id, Option<name>) {}

/// Compute the number of exit relay based on two metrics:
/// 1. Tor is mainly single thread
/// 2. For exit relay is good to have at least 500/700M memory space
pub fn how_many_relay(memory: u64, n_cpus: usize) -> u64 {
    // the low bound between cores and memory
    cmp::min((memory >> 20) / RELAY_MEMORY_BOUND, n_cpus as u64)
}

#[test]
fn test_how_many_relay() {
    assert_eq!(how_many_relay(16563834880, 10), 10);
    assert_eq!(how_many_relay(16563834880, 100), 22);
}
