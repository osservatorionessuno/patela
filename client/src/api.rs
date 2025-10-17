use std::time::Duration;

use reqwest::{Client, tls};

use crate::SERVER_CA;

const SERVER_TIMEOUT_SEC: u64 = 5;

pub async fn build_client() -> Result<Client, reqwest::Error> {
    let builder = reqwest::Client::builder()
        .use_rustls_tls()
        .min_tls_version(tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .https_only(true)
        .timeout(Duration::from_secs(SERVER_TIMEOUT_SEC));

    // If available use embedded Authority
    let builder = if let Some(server_authority) = SERVER_CA {
        let cert = reqwest::Certificate::from_pem(server_authority)?;
        builder.add_root_certificate(cert)
    } else {
        builder
    };

    builder.build()
}
