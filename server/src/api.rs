use serde::{Deserialize, Serialize};
use tss_esapi::structures::{Attest, Public, Signature};

use crate::{NetworkConf, SystemConf, TorRelayConf};

// Define the api common structures for client and server

pub struct CreateRequest {
    pub ak_public: Public,
    pub ek_public: Public,
}

#[derive(Debug)]
pub struct ValidateRequest {
    pub ak_public: Public,
    pub signature: Signature,
    pub attest: Attest,
}

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
