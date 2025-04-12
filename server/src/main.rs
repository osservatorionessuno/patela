use actix_tls::accept::rustls_0_23::TlsStream;
use actix_web::{
    App, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder,
    dev::{Extensions, ServiceRequest},
    error::{ErrorNotFound, ErrorUnauthorized},
    get, middleware, post,
    rt::net::TcpStream,
    web::{self, Bytes, Data, Json, Path},
};
use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};
use biscuit_auth::{Biscuit, PrivateKey, PublicKey, macros::biscuit};
use clap::Parser;
use clap::clap_derive::Subcommand;
use clap_verbosity_flag::Verbosity;
use log::info;
use patela_server::{api::*, db::*, *};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use sha256::digest;
use std::{any::Any, env, fs::File, io::BufReader, path::PathBuf, sync::Arc};
use x509_parser::nom::AsBytes;

use actix_web::error::ErrorInternalServerError;
use sqlx::SqlitePool;

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Run patela web server
    Run {
        /// bind local ip
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        /// bind port for tls server
        #[arg(long, default_value_t = 8020)]
        port: u16,
        /// tls authority cert
        #[arg(long, default_value = "certs/cantina-ca-cert.pem")]
        ca_cert: PathBuf,
        /// tls server certificate
        #[arg(long, default_value = "certs/cantina-server-cert.pem")]
        server_cert: PathBuf,
        /// tls server key
        #[arg(long, default_value = "certs/cantina-server-key.pem")]
        server_key: PathBuf,
        /// biscuit private key
        #[arg(long, env = "PATELA_BISCUIT_KEY")]
        biscuit_key: String,
    },
    /// List nodes and relays
    List,
    /// Remove node and stored conf
    Remove { id: i64 },
}

#[derive(Debug, Clone, Parser)]
struct Config {
    #[command(subcommand)]
    cmd: Commands,
    #[command(flatten)]
    verbose: Verbosity,
    /// use abs path as `sqlite:$PWD/patela.db`
    #[arg(long, env = "PATELA_DATABASE_URL", default_value = "sqlite:patela.db")]
    database_url: String,
}

struct PatelaServer {
    db: SqlitePool,
    biscuit_root: biscuit_auth::KeyPair,
}

async fn node_id_from_request(req: &HttpRequest, pub_key: PublicKey) -> anyhow::Result<i64> {
    let credentials = BearerAuth::extract(req).await?;
    let token = Biscuit::from_base64(credentials.token(), pub_key)?;

    let res: Vec<(i64, String)> = token
        .authorizer()?
        .query("data($id, $digest) <- node($id, $digest)")?;

    let (node_id, _) = res
        .first()
        .ok_or(anyhow::format_err!("Invalid token content"))?
        .to_owned();

    Ok(node_id)
}

#[post("/create")]
async fn create(app: Data<PatelaServer>, req: HttpRequest) -> actix_web::Result<impl Responder> {
    let client_cert = req
        .conn_data::<CertificateDer<'static>>()
        .unwrap()
        .as_bytes();

    // TODO: replace cert with public ek key of the tpm
    let cert_digest = digest(client_cert);

    Ok(Json(ApiNodeCreateResponse {
        id: create_node(&app.db, &cert_digest)
            .await
            .map_err(ErrorInternalServerError)?,
    }))
}

#[get("/auth")]
async fn auth(app: Data<PatelaServer>, req: HttpRequest) -> actix_web::Result<impl Responder> {
    let client_cert = req
        .conn_data::<CertificateDer<'static>>()
        .unwrap()
        .as_bytes();
    let cert_digest = digest(client_cert);

    let node = get_node_by_cert(&app.db, &cert_digest)
        .await
        .map_err(ErrorInternalServerError)?;

    let node_id = node.id;

    let authority = biscuit!(
        r#"
      node({node_id}, {cert_digest});
      "#
    );

    // NOTE: add time attenuation
    // check if time($time), $time <= 2021-12-20T00:00:00Z;

    let token = authority
        .build(&app.biscuit_root)
        .map_err(ErrorInternalServerError)?;

    let payload = token.to_base64().map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().body(payload))
}

#[get("/node/key")]
async fn get_node_key(
    app: Data<PatelaServer>,
    req: HttpRequest,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    let (key, _) = get_node_key_and_nonce(&app.db, node_id)
        .await
        .map_err(ErrorNotFound)?;

    let key = key.ok_or(ErrorNotFound("No key found"))?;

    Ok(HttpResponse::Ok().body(key))
}

#[post("/node/key")]
async fn post_node_key(
    app: Data<PatelaServer>,
    req: HttpRequest,
    body: Bytes,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    update_node_aes_key(&app.db, node_id, body.to_vec())
        .await
        .map_err(ErrorNotFound)?;

    Ok(HttpResponse::Ok())
}

#[get("/node/nonce")]
async fn get_node_nonce(
    app: Data<PatelaServer>,
    req: HttpRequest,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    let (_, nonce) = get_node_key_and_nonce(&app.db, node_id)
        .await
        .map_err(ErrorNotFound)?;

    let nonce = nonce.ok_or(ErrorNotFound("No nonce found"))?;

    Ok(HttpResponse::Ok().body(nonce))
}

#[post("/node/nonce")]
async fn post_node_nonce(
    app: Data<PatelaServer>,
    req: HttpRequest,
    body: Bytes,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    update_node_aes_nonce(&app.db, node_id, body.to_vec())
        .await
        .map_err(ErrorNotFound)?;

    Ok(HttpResponse::Ok())
}

#[post("/specs")]
async fn specs(
    app: Data<PatelaServer>,
    req: HttpRequest,
    specs: Json<HwSpecs>,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    match create_node_spec(&app.db, node_id, &specs).await {
        Err(err) => Err(ErrorInternalServerError(err)),
        Ok(_) => Ok(HttpResponse::Ok()),
    }
}

#[get("/relays")]
async fn relays(app: Data<PatelaServer>, req: HttpRequest) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    // look for relays already created
    let mut tor_relays = get_relays(&app.db, node_id).await.map_err(ErrorNotFound)?;

    // Relay conf are created lazy
    if tor_relays.is_empty() {
        // find last valid specs
        let spec = get_last_node_spec(&app.db, node_id)
            .await
            .map_err(ErrorInternalServerError)?;

        // calculate how many
        let n_relays = how_many_relay(spec.memory, spec.n_cpus);

        for _ in 0..n_relays {
            let (cheese_id, _) = allocate_cheese(&app.db)
                .await
                .map_err(ErrorInternalServerError)?;

            let (ipv4, ipv6) = find_next_ips(&app.db)
                .await
                .map_err(ErrorInternalServerError)?;

            let _ = create_relay(
                &app.db,
                node_id,
                cheese_id,
                ipv4.to_string().as_str(),
                ipv6.to_string().as_str(),
            )
            .await
            .map_err(ErrorInternalServerError)?;
        }
        // Reload relays from db, this is redundand and can be done in the create
        tor_relays = get_relays(&app.db, node_id)
            .await
            .map_err(ErrorInternalServerError)?;
    }

    // NOTE: assume gigabit port, maybe the client should decide on this
    let relay_rate = 1024 / tor_relays.iter().len() as u16;
    let relay_burst = relay_rate; // burst should be at least same than rate

    // NOTE: we don't put effort on calculate the family from db because we are waiting for `happy
    // family` feature from tor
    let relays_family = env::var("PATELA_RELAY_FAMILY").unwrap_or("".to_string());

    let relay_policy = vec![
        TorPolicy {
            verb: TorPolicyVerb::Reject,
            object: "0.0.0.0/8:*".to_string(),
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
    ];

    let relays_conf = tor_relays
        .iter()
        .map(|elem| TorRelayConf {
            name: elem.name.clone(),
            family: relays_family.clone(),
            policy: relay_policy.clone(),
            bandwidth_rate: relay_rate,
            bandwidth_burst: relay_burst,
            or_port: RELAY_OR_PORT,
            or_address_v4: elem.ip_v4.clone(),
            or_address_v6: elem.ip_v6.clone(),
        })
        .collect::<Vec<TorRelayConf>>();

    Ok(Json(ApiRelaysResponse {
        network: NetworkConf {
            ipv4_gateway: GATEWAY_V4.to_string(),
            ipv4_prefix: *PREFIX_V4,
            ipv6_gateway: GATEWAY_V6.to_string(),
            ipv6_prefix: *PREFIX_V6,
            dns_server: DNS_SERVER.to_string(),
        },
        relays: relays_conf,
    }))
}

#[get("/relays/data/{name}")]
async fn get_relay_data(
    app: Data<PatelaServer>,
    path: Path<String>,
    req: HttpRequest,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    let data = get_data(&app.db, node_id, &path.into_inner())
        .await
        .map_err(ErrorNotFound)?;

    Ok(HttpResponse::Ok().body(data))
}

#[post("/relays/data/{name}")]
async fn post_relay_data(
    app: Data<PatelaServer>,
    path: Path<String>,
    req: HttpRequest,
    body: Bytes,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    let relay_id = get_relay_by_name(&app.db, node_id, &path.into_inner())
        .await
        .map_err(ErrorInternalServerError)?;

    let _ = insert_data(&app.db, relay_id, body.to_vec())
        .await
        .map_err(ErrorInternalServerError)?;

    Ok(HttpResponse::Ok())
}

async fn ok_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    let app = req.app_data::<Data<PatelaServer>>().unwrap();

    if Biscuit::from_base64(credentials.token(), app.biscuit_root.public()).is_err() {
        return Err((ErrorUnauthorized("bearer parse error"), req));
    }

    Ok(req)
}

fn get_client_cert(connection: &dyn Any, data: &mut Extensions) {
    if let Some(tls_socket) = connection.downcast_ref::<TlsStream<TcpStream>>() {
        info!("TLS on_connect");

        let (_, tls_session) = tls_socket.get_ref();

        if let Some(certs) = tls_session.peer_certificates() {
            info!("client certificate found");

            // insert a `rustls::Certificate` into request data
            data.insert(certs.last().unwrap().clone());
        }
    } else if connection.downcast_ref::<TcpStream>().is_some() {
        info!("plaintext on_connect");
    }
}

async fn cmd_run(
    db_pool: SqlitePool,
    host: String,
    port: u16,
    ca_cert: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    biscuit_key: String,
) -> std::io::Result<()> {
    let shared_data = Data::new(PatelaServer {
        db: db_pool,
        biscuit_root: biscuit_auth::KeyPair::from(
            &PrivateKey::from_bytes_hex(&biscuit_key).unwrap(),
        ),
    });

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let mut cert_store = RootCertStore::empty();

    // import CA cert
    let ca_cert = &mut BufReader::new(File::open(ca_cert)?);
    let ca_cert = certs(ca_cert).collect::<Result<Vec<_>, _>>().unwrap();

    for cert in ca_cert {
        cert_store.add(cert).expect("root CA not added to store");
    }

    // set up client authentication requirements
    let client_auth = WebPkiClientVerifier::builder(Arc::new(cert_store))
        .build()
        .unwrap();
    let config = ServerConfig::builder().with_client_cert_verifier(client_auth);

    // import server cert and key
    let cert_file = &mut BufReader::new(File::open(server_cert)?);
    let key_file = &mut BufReader::new(File::open(server_key)?);

    let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>().unwrap();
    let mut keys = pkcs8_private_keys(key_file)
        .map(|key| key.map(PrivateKeyDer::Pkcs8))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let config = config.with_single_cert(cert_chain, keys.remove(0)).unwrap();

    HttpServer::new(move || {
        App::new()
            .app_data(shared_data.clone())
            .service(web::scope("/public").service(create).service(auth))
            .service(
                web::scope("/private")
                    .wrap(HttpAuthentication::bearer(ok_validator))
                    .service(specs)
                    .service(relays)
                    .service(get_node_key)
                    .service(get_node_nonce)
                    .service(post_node_key)
                    .service(post_node_nonce)
                    .service(get_relay_data)
                    .service(post_relay_data),
            )
            .wrap(middleware::Logger::new("%t %s %U"))
    })
    .on_connect(get_client_cert)
    .bind_rustls_0_23((host, port), config)?
    .workers(1)
    .run()
    .await
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    env_logger::Builder::new()
        .filter_level(config.verbose.log_level_filter())
        .init();

    let pool = SqlitePool::connect(&config.database_url).await.unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();

    match config.cmd {
        Commands::Run {
            host,
            port,
            ca_cert,
            server_cert,
            server_key,
            biscuit_key,
        } => {
            cmd_run(
                pool,
                host,
                port,
                ca_cert,
                server_cert,
                server_key,
                biscuit_key,
            )
            .await?;
        }
        Commands::List => {
            // Fetch all nodes
            let nodes = get_nodes(&pool).await?;

            // Fetch all relays by node
            for node in nodes {
                println!("Node id:\t\t{}", node.id);
                println!("Node cert:\t\t{}", node.cert);
                println!("First seen:\t{}", node.first_seen);
                println!("Last seen:\t{}", node.last_seen);

                println!("Relays:");

                for relay in get_relays(&pool, node.id).await? {
                    println!("\t{}\t\t{}\t{}", relay.name, relay.ip_v4, relay.ip_v6);
                }
            }
        }
        Commands::Remove { id } => {
            let _ = remove_node(&pool, id).await;
            println!("Removed node {}", id);
        }
    }
    Ok(())
}
