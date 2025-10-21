use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::{cmp, env};

pub mod db;
pub mod tor_config;
pub mod tpm;

lazy_static! {
    static ref RELAY_MEMORY_BOUND: u64 = env::var("PATELA_RELAY_MEMORY_BOUND")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);
    pub static ref RELAY_OR_PORT: u16 = env::var("PATELA_RELAY_OR_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9001);
}

/// This is not used now because we assume dhcp server working correctly
#[derive(Serialize, Deserialize, Debug)]
pub struct NetworkConf {
    pub ipv4_gateway: String,
    pub ipv6_gateway: String,
    pub dns_server: Option<String>,
    pub interface_name: Option<String>,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeConfig {
    pub network: NetworkConf,
}

/// Compute the number of exit relay based on two metrics:
/// 1. Tor is mainly single thread
/// 2. For exit relay is good to have at least 500/700M memory space
pub fn how_many_relay(memory: u64, n_cpus: usize) -> u64 {
    // the low bound between cores and memory
    cmp::min((memory >> 20) / *RELAY_MEMORY_BOUND, n_cpus as u64)
}

#[test]
fn test_how_many_relay() {
    assert_eq!(how_many_relay(16563834880, 10), 10);
    assert_eq!(how_many_relay(16563834880, 100), 15);
}
