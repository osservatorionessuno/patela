use serde::{Deserialize, Serialize};

use crate::{NetworkConf, SystemConf, TorRelayConf};

// Define the api common structures for client and server

#[derive(Debug)]
pub struct ConfigResponse {
    pub tor: TorRelayConf,
    pub network: NetworkConf,
    pub patela: SystemConf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNodeCreateResponse {
    pub id: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiNodeSpecsResponse {
    pub system: SystemConf,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ApiRelaysResponse {
    pub network: NetworkConf,
    pub relays: Vec<TorRelayConf>,
}
