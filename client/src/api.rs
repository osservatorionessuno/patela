use std::time::Duration;

use reqwest::{Client, tls};
use serde::{Deserialize, Serialize};
use tss_esapi::structures::Public;

use crate::SERVER_CA;

const SERVER_TIMEOUT_SEC: u64 = 5;

#[derive(Debug, Clone, Serialize)]
pub struct AuthRequest {
    pub ek_public: Public,
    pub ak_public: Public,
    pub ak_name: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthChallenge {
    pub blob: Vec<u8>,
    pub secret: Vec<u8>,
}

pub async fn build_client(insecure: bool) -> Result<Client, reqwest::Error> {
    let builder = reqwest::Client::builder()
        .use_rustls_tls()
        .min_tls_version(tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .https_only(true)
        .timeout(Duration::from_secs(SERVER_TIMEOUT_SEC));

    // If insecure mode is enabled, skip certificate validation
    let builder = if insecure {
        builder.danger_accept_invalid_certs(true)
    } else {
        // If available use embedded Authority
        if let Some(server_authority) = SERVER_CA {
            let cert = reqwest::Certificate::from_pem(server_authority)?;
            builder.add_root_certificate(cert)
        } else {
            builder
        }
    };

    builder.build()
}
