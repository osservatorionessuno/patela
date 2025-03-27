use serde::{Deserialize, Serialize};
use std::{
    cmp,
    fmt::{self, Display},
};

pub mod api;
pub mod db;

const RELAY_MEMORY_BOUND: u64 = 700;
pub const RELAY_OR_PORT: u16 = 9001;

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
    pub ipv6_gateway: String,
    pub dns_server: Option<String>,
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
    //pub network: Vec<HwSpecsNetwork>,
}

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
