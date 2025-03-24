use std::time::Duration;

use reqwest::{Client, tls};

use crate::{CLIENT_KEY_CERT, SERVER_CA};

const SERVER_TIMEOUT_SEC: u64 = 5;

pub async fn build_client() -> Result<Client, reqwest::Error> {
    let cert = reqwest::Certificate::from_pem(SERVER_CA)?;

    // NOTE: the key cert is the concatenation of the two pem files
    let client_key_cert = reqwest::Identity::from_pem(CLIENT_KEY_CERT)?;

    reqwest::Client::builder()
        .use_rustls_tls()
        .min_tls_version(tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .add_root_certificate(cert)
        .identity(client_key_cert)
        .https_only(true)
        .timeout(Duration::from_secs(SERVER_TIMEOUT_SEC))
        .build()
}
