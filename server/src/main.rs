use actix_tls::accept::rustls_0_23::TlsStream;
use actix_web::{
    App, FromRequest, HttpRequest, HttpResponse, HttpServer, Responder,
    dev::{Extensions, ServiceRequest},
    error::{ErrorInternalServerError, ErrorNotFound, ErrorUnauthorized},
    get, middleware, post,
    rt::net::TcpStream,
    web::{self, Data, Json, Path},
};
use serde::{Deserialize, Serialize};
use tss_esapi::structures::Public;
use tss_esapi::traits::Marshall;

use std::io::Read;

use actix_web_httpauth::{extractors::bearer::BearerAuth, middleware::HttpAuthentication};
use biscuit_auth::{Biscuit, PrivateKey, PublicKey, macros::biscuit};
use clap::{Args, Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
use colored::Colorize;
use log::info;
use patela_server::{db::*, tor_config::TorConfigParser, *};
use rustls::{RootCertStore, ServerConfig, pki_types::PrivateKeyDer, server::WebPkiClientVerifier};
use rustls_pemfile::{certs, pkcs8_private_keys};
use sha2::Digest as _;
use sha256::digest;
use sqlx::SqlitePool;
use std::{any::Any, fs::File, io::BufReader, path::PathBuf, sync::Arc};

#[derive(Debug, Args, Clone)]
struct GlobalOpts {
    #[command(flatten)]
    verbose: Verbosity,
    /// use abs path as `sqlite:$PWD/patela.db`
    #[arg(long, env = "PATELA_DATABASE_URL", default_value = "sqlite:patela.db")]
    database_url: String,
}

#[derive(Debug, Args, Clone)]
struct CmdRunArgs {
    /// bind local ip
    #[clap(long, default_value = "0.0.0.0")]
    host: String,
    /// bind port for tls server
    #[clap(long, default_value_t = 8020)]
    port: u16,
    /// tls authority cert
    #[clap(long, default_value = "certs/ca-cert.pem")]
    ca_cert: PathBuf,
    /// tls server certificate
    #[clap(long, default_value = "certs/server-cert.pem")]
    server_cert: PathBuf,
    /// tls server key
    #[clap(long, default_value = "certs/server-key.pem")]
    server_key: PathBuf,
    /// biscuit private key
    #[clap(long, env = "PATELA_BISCUIT_KEY")]
    biscuit_key: String,
}

#[derive(Subcommand, Clone, Debug)]
enum CmdListScope {
    /// All nodes and relays
    All,
    /// A node is an OS that runs one or more relays
    Node,
    /// Single tor relay
    Relay,
}

#[derive(Subcommand, Clone, Debug)]
enum CmdVerbScope {
    /// Fallback configuration for all the relays
    Default,
    /// Node-specific configuration override
    Node {
        /// Node ID
        #[arg(long)]
        id: i64,
    },
    /// Relay-specific configuration override
    Relay {
        /// Relay name (cheese name)
        #[arg(long)]
        id: String,
    },
}

#[derive(Clone, Debug)]
enum InputSource {
    Stdin,
    File(PathBuf),
}

impl std::str::FromStr for InputSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "-" {
            Ok(InputSource::Stdin)
        } else {
            Ok(InputSource::File(PathBuf::from(s)))
        }
    }
}

#[derive(Debug, Subcommand, Clone)]
enum CmdConfVerb {
    /// Parse a torrc file and set configuration at different scopes
    Import {
        /// Input file, `-` for stdin
        #[arg()]
        input: InputSource,
        /// Configuration scope
        #[command(subcommand)]
        scope: CmdVerbScope,
    },
    /// Configure a configuration
    Set {
        #[command(subcommand)]
        scope: CmdVerbScope,
        /// TODO: use torvalue
        directive: Option<String>,
        value: Option<String>,
    },
    /// Read a configuration
    Get {
        #[command(subcommand)]
        scope: CmdVerbScope,
        /// Json format
        #[arg(short, long)]
        json: bool,
    },
    /// Remove a configuration
    Remove {
        #[command(subcommand)]
        scope: CmdVerbScope,
        directive: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    /// Run patela web server
    Run(CmdRunArgs),
    /// List nodes and relays
    List {
        // TODO: default to all
        #[command(subcommand)]
        resource: CmdListScope,
        /// limit the result by name
        #[arg()]
        filter: Option<String>,
    },
    /// Handle global, node and relay configurations
    Conf {
        #[command(subcommand)]
        verb: CmdConfVerb,
    },
    /// Enable a node (allow authentication and relay creation)
    Enable {
        /// Node ID to enable
        node_id: i64,
    },
    /// Disable a node (block authentication)
    Disable {
        /// Node ID to disable
        node_id: i64,
    },
}

#[derive(Debug, Clone, Parser)]
struct PatelaArgs {
    #[clap(flatten)]
    global_opts: GlobalOpts,
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthRequest {
    ek_public: Public,
    ak_public: Public,
}

/// Long running web server and internal states
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

// Node creation is now handled by the /auth endpoint via TPM attestation

#[derive(Debug, Clone, Serialize)]
struct AuthChallenge {
    blob: Vec<u8>,
    secret: Vec<u8>,
}

#[post("/auth")]
async fn auth(
    app: Data<PatelaServer>,
    body: Json<AuthRequest>,
) -> actix_web::Result<impl Responder> {
    let auth_req = body.into_inner();

    // Marshall public keys to hex strings for database storage
    let ek_bytes = auth_req
        .ek_public
        .marshall()
        .map_err(ErrorInternalServerError)?;
    let ak_bytes = auth_req
        .ak_public
        .marshall()
        .map_err(ErrorInternalServerError)?;

    let ek_public_hex = hex::encode(&ek_bytes);
    let ak_public_hex = hex::encode(&ak_bytes);

    // Get or create node by EK public key
    let node = get_or_create_node_by_ek(&app.db, &ek_public_hex, &ak_public_hex)
        .await
        .map_err(ErrorInternalServerError)?;

    // Check if node is enabled (manual approval required)
    if !node.enabled {
        return Err(ErrorUnauthorized(
            "Node is not yet enabled. Call the hotline.",
        ));
    }

    // Create a biscuit token that will be the session token
    let node_id = node.id;
    let ek_digest = digest(&ek_bytes);

    let authority = biscuit!(
        r#"
        node({node_id}, {ek_digest});
        "#
    );

    let token = authority
        .build(&app.biscuit_root)
        .map_err(ErrorInternalServerError)?;

    // The biscuit token bytes become the challenge
    let challenge_bytes = token.to_vec().map_err(ErrorInternalServerError)?;

    // Get the AK name from the AK public key
    let ak_name = tss_esapi::structures::Name::try_from(sha2::Sha256::digest(&ak_bytes).to_vec())
        .map_err(ErrorInternalServerError)?;

    // Create attestation credentials - encrypt the biscuit token
    let (blob, secret) = patela_server::tpm::create_attestation_credentials(
        auth_req.ek_public,
        ak_name,
        &challenge_bytes,
    )
    .map_err(ErrorInternalServerError)?;

    // Marshal the blob and secret to bytes for JSON serialization
    let blob_bytes = blob.to_vec();
    let secret_bytes = secret.to_vec();

    Ok(HttpResponse::Ok().json(AuthChallenge {
        blob: blob_bytes,
        secret: secret_bytes,
    }))
}

#[get("/config/node")]
async fn get_config_node(
    app: Data<PatelaServer>,
    req: HttpRequest,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    // look for relays already created
    let mut tor_relays = get_relays_conf(&app.db, node_id)
        .await
        .map_err(ErrorNotFound)?;

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

            let relay_id = create_relay(
                &app.db,
                node_id,
                cheese_id,
                ipv4.to_string().as_str(),
                ipv6.to_string().as_str(),
                None,
                None,
            )
            .await
            .map_err(ErrorInternalServerError)?;

            let _resolved_conf = get_resolved_relay_conf(&app.db, node_id, relay_id)
                .await
                .map_err(ErrorInternalServerError)?;
        }

        // Reload relays from db, this is redundand and can be done in the create
        tor_relays = get_relays_conf(&app.db, node_id)
            .await
            .map_err(ErrorInternalServerError)?;
    }

    Ok(Json(tor_relays))
}

#[get("/config/resolved/node")]
async fn get_config_resolved_node(
    app: Data<PatelaServer>,
    req: HttpRequest,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    Ok(Json(
        get_resolved_node_conf(&app.db, node_id)
            .await
            .map_err(ErrorInternalServerError)?,
    ))
}

#[post("/specs")]
async fn post_specs(
    app: Data<PatelaServer>,
    req: HttpRequest,
    body: Json<HwSpecs>,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    let spec_id = create_node_spec(&app.db, node_id, &body.into_inner())
        .await
        .map_err(ErrorInternalServerError)?;

    Ok(Json(serde_json::json!({ "id": spec_id })))
}

#[get("/config/resolved/{relay_name}")]
async fn get_config_resolved_relay(
    app: Data<PatelaServer>,
    path: Path<String>,
    req: HttpRequest,
) -> actix_web::Result<impl Responder> {
    let node_id = node_id_from_request(&req, app.biscuit_root.public())
        .await
        .map_err(ErrorNotFound)?;

    let relay_name = path.into_inner();
    let relay_id = get_relay_by_name(&app.db, node_id, &relay_name)
        .await
        .map_err(ErrorNotFound)?;

    let resolved_conf = get_resolved_relay_conf(&app.db, node_id, relay_id)
        .await
        .map_err(ErrorInternalServerError)?;

    Ok(Json(resolved_conf))
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

/// Helper function to filter out ORPort and Nickname directives from TorConfig
fn filter_tor_config(
    conf: &patela_server::tor_config::TorConfig,
) -> patela_server::tor_config::TorConfig {
    use std::collections::HashMap;

    let mut filtered = patela_server::tor_config::TorConfig {
        directives: HashMap::new(),
    };

    for (key, values) in &conf.directives {
        if key.to_lowercase() != "orport" && key.to_lowercase() != "nickname" {
            filtered.directives.insert(key.clone(), values.clone());
        }
    }

    filtered
}

/// Helper function to get node_id and relay_id from relay name
async fn get_relay_ids(pool: &SqlitePool, relay_name: &str) -> anyhow::Result<(i64, i64)> {
    let nodes = get_nodes(pool).await?;

    for node in nodes {
        if let Ok(relay_id) = get_relay_by_name(pool, node.id, relay_name).await {
            return Ok((node.id, relay_id));
        }
    }

    anyhow::bail!("Relay '{}' not found", relay_name)
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
            &PrivateKey::from_bytes_hex(&biscuit_key, biscuit_auth::builder::Algorithm::Ed25519)
                .unwrap(),
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
            .service(web::scope("/public").service(auth))
            .service(
                web::scope("/private")
                    .wrap(HttpAuthentication::bearer(ok_validator))
                    .service(get_config_resolved_node)
                    .service(get_config_resolved_relay)
                    .service(post_specs),
            )
            .wrap(middleware::Logger::new("%t %s %U"))
    })
    .on_connect(get_client_cert)
    .bind_rustls_0_23((host, port), config)?
    .run()
    .await
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let config = PatelaArgs::parse();
    env_logger::Builder::new()
        .filter_level(config.global_opts.verbose.log_level_filter())
        .init();

    let pool = SqlitePool::connect(&config.global_opts.database_url)
        .await
        .unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();

    match config.cmd {
        Commands::Run(run_conf) => {
            cmd_run(
                pool,
                run_conf.host,
                run_conf.port,
                run_conf.ca_cert,
                run_conf.server_cert,
                run_conf.server_key,
                run_conf.biscuit_key,
            )
            .await?;
        }
        Commands::List {
            resource: _,
            filter: _,
        } => {
            // Fetch all nodes
            let nodes = get_nodes(&pool).await?;

            // Fetch all relays by node
            for node in nodes {
                println!(
                    "\n{} {}",
                    "Node".bright_magenta().bold(),
                    node.id.to_string().cyan()
                );
                let ek_preview = if node.ek_public.len() > 32 {
                    format!("{}...", &node.ek_public[..32])
                } else {
                    node.ek_public.clone()
                };
                println!(
                    "  {} {}",
                    "EK Public:".bright_black(),
                    ek_preview.bright_black()
                );
                let ak_preview = if node.ak_public.len() > 32 {
                    format!("{}...", &node.ak_public[..32])
                } else {
                    node.ak_public.clone()
                };
                println!(
                    "  {} {}",
                    "AK Public:".bright_black(),
                    ak_preview.bright_black()
                );
                println!(
                    "  {} {}",
                    "First seen: ".bright_black(),
                    node.first_seen.green()
                );
                println!(
                    "  {} {}",
                    "Last seen:  ".bright_black(),
                    node.last_seen.green()
                );

                let status_text = if node.enabled {
                    "enabled".green().bold()
                } else {
                    "disabled".red().bold()
                };
                println!("  {} {}", "Status:     ".bright_black(), status_text);

                let relays = get_relays_conf(&pool, node.id).await?;
                if !relays.is_empty() {
                    println!("\n  {}:", "Relays".bright_yellow().bold());
                    for relay in relays {
                        println!(
                            "    {} {} {}",
                            relay.name.cyan().bold(),
                            relay.ip_v4.white(),
                            relay.ip_v6.bright_black()
                        );
                    }
                }
            }
            println!();
        }
        Commands::Conf { verb } => match verb {
            CmdConfVerb::Import { input, scope } => {
                // Read input from file or stdin
                let content = match input {
                    InputSource::Stdin => {
                        let mut buffer = String::new();
                        std::io::stdin().read_to_string(&mut buffer)?;
                        buffer
                    }
                    InputSource::File(path) => std::fs::read_to_string(path)?,
                };

                // Parse torrc configuration
                let tor_conf = TorConfigParser::parse(&content)?;

                match scope {
                    CmdVerbScope::Default => {
                        // Filter out ORPort and Nickname for global config
                        let filtered_conf = filter_tor_config(&tor_conf);
                        set_global_tor_conf(&pool, &filtered_conf).await?;
                        println!(
                            "{} {}",
                            "✓".green().bold(),
                            "Global default configuration imported successfully".green()
                        );
                    }
                    CmdVerbScope::Node { id } => {
                        // Filter out ORPort and Nickname for node config
                        let filtered_conf = filter_tor_config(&tor_conf);
                        set_node_tor_conf(&pool, id, &filtered_conf).await?;
                        println!(
                            "{} Node {} configuration imported successfully",
                            "✓".green().bold(),
                            id.to_string().cyan()
                        );
                    }
                    CmdVerbScope::Relay { id } => {
                        // No filtering for relay config
                        let (_node_id, relay_id) = get_relay_ids(&pool, &id).await?;
                        set_relay_tor_conf(&pool, relay_id, &tor_conf).await?;
                        println!(
                            "{} Relay '{}' (id:{}) configuration imported successfully",
                            "✓".green().bold(),
                            id.cyan(),
                            relay_id.to_string().yellow()
                        );
                    }
                }
            }
            CmdConfVerb::Get { scope, json } => {
                let conf = match scope {
                    CmdVerbScope::Default => get_global_tor_conf(&pool).await?,
                    CmdVerbScope::Node { id } => get_node_tor_conf(&pool, id).await?,
                    CmdVerbScope::Relay { id } => {
                        let (_, relay_id) = get_relay_ids(&pool, &id).await?;
                        get_relay_tor_conf(&pool, relay_id).await?
                    }
                };

                match conf {
                    Some(c) => {
                        if json {
                            println!("{}", c.to_json()?);
                        } else {
                            // Pretty print as torrc format
                            for (key, values) in &c.directives {
                                for value in values {
                                    println!(
                                        "{} {}",
                                        key.bright_blue().bold(),
                                        value.to_string().white()
                                    );
                                }
                            }
                        }
                    }
                    None => println!("{} {}", "ℹ".blue(), "No configuration found".yellow()),
                }
            }
            CmdConfVerb::Set {
                scope: _,
                directive: _,
                value: _,
            } => {
                anyhow::bail!(
                    "Set command not yet implemented. Use 'import' to set configurations from torrc files"
                );
            }
            CmdConfVerb::Remove {
                scope: _,
                directive: _,
            } => {
                anyhow::bail!("Remove command not yet implemented");
            }
        },
        Commands::Enable { node_id } => {
            enable_node(&pool, node_id).await?;
            println!(
                "{} Node {} {}",
                "✓".green().bold(),
                node_id.to_string().cyan(),
                "enabled successfully".green()
            );
        }
        Commands::Disable { node_id } => {
            disable_node(&pool, node_id).await?;
            println!(
                "{} Node {} {}",
                "✓".green().bold(),
                node_id.to_string().cyan(),
                "disabled successfully".yellow()
            );
        }
    }
    Ok(())
}
