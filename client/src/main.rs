use std::{ffi::CString, fs, os::unix::fs::chown, path::Path, process::Command, time::Duration};

use aes_gcm::aead::Aead;
use clap::Parser;
use clap::clap_derive::Subcommand;
use etc_passwd::Passwd;
use ipnetwork::{Ipv4Network, Ipv6Network};
use patela_client::{api::build_client, tpm::*, *};
use patela_server::{NetworkConf, TorRelayConf, api::NodeConf};
use systemctl::SystemCtl;
use tar::Archive;
use tss_esapi::{Context, TctiNameConf, handles::KeyHandle};

#[derive(Subcommand, Debug, Clone)]
enum NetCommands {
    Add,
    List,
}

#[derive(Subcommand, Debug, Clone)]
enum TpmCommands {
    ListPersistent,
    CleanPersistent,
    CreatePrimary,
    Encrypt,
    Decrypt,
    Test,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Start {
        #[arg(long, action, help = "Do not run network setup")]
        skip_net: bool,
        #[arg(long, action, help = "Do not try to restore backup from server")]
        skip_backup: bool,
    },
    /// Mainly for development and basic maintenances
    Tpm {
        #[command(subcommand)]
        cmd: TpmCommands,
    },
    /// Mainly for development and basic maintenances
    Net {
        #[command(subcommand)]
        cmd: NetCommands,
    },
}

#[derive(Debug, Clone, Parser)]
struct Config {
    #[command(subcommand)]
    cmd: Option<Commands>,
    /// bind local ip
    #[arg(long, default_value = PATELA_SERVER )]
    server: String,
    /// tpm device, use `TCTI` env variable for swtpm
    #[arg(long)]
    tpm2: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();

    println!("Starting patela...");

    match config.cmd.unwrap_or(Commands::Start {
        skip_net: false,
        skip_backup: false,
    }) {
        Commands::Start {
            skip_net,
            skip_backup,
        } => cmd_start(config.server, config.tpm2, skip_net, skip_backup).await,
        Commands::Tpm { cmd } => cmd_tpm(cmd, config.tpm2).await,
        Commands::Net { cmd } => cmd_net(cmd).await,
    }
}

// Yes this is big, but that's life
async fn cmd_start(
    server_url: String,
    tpm2: Option<String>,
    skip_net: bool,
    skip_backup: bool,
) -> anyhow::Result<()> {
    let tpm_device_name = match tpm2 {
        Some(device) => TctiNameConf::Device(device.parse()?),
        None => TctiNameConf::from_environment_variable()?,
    };

    let context = &mut Context::new(tpm_device_name)?;

    // If the key are found in the tpm assume is not the first run
    // In other case create and get the id
    let (_primary_key, is_first_run): (KeyHandle, bool) =
        match find_persistent_handle(context, get_persistent_handler()) {
            Some(object) => (object.into(), false),
            None => (create_and_persist(context), true),
        };

    match is_first_run {
        true => println!("This is the first boot for patela!"),
        false => println!("This is not my first time here!"),
    }

    let client = build_client().await?;

    if is_first_run {
        let node_id = client
            .post(format!("{}/public/create", server_url))
            .send()
            .await?
            .error_for_status()?
            .json::<i64>()
            .await?;

        println!("Create new node on the server with id {}", node_id);
    }

    // Authenticate with server
    let session_token = client
        .get(format!("{}/public/auth", server_url))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    println!("Succesfuly authenticathed with server");

    // Generate or fetch aes key and nonce
    let (cipher, nonce) = match is_first_run {
        true => {
            println!("Generate aes-gcm key and nonce for bkp encryption...");
            generate_aes_cipher_and_store(context, &client, &server_url, &session_token).await
        }
        false => {
            println!("Restore encrypted aes-gcm key and nonce from server...");
            fetch_aes_key(context, &client, &server_url, &session_token).await
        }
    }?;

    // Configuration are send in any case
    let specs = collect_specs()?;

    println!("Push collected specs {:?}\n", specs);

    // Get system configuration in response of hw specs
    client
        .post(format!("{}/private/specs", server_url))
        .bearer_auth(&session_token)
        .json(&specs)
        .send()
        .await?
        .error_for_status()?;

    println!("Fetch relays conf");

    // Get tor relay conf
    let relays = client
        .get(format!("{}/private/relays", server_url))
        .bearer_auth(&session_token)
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<TorRelayConf>>()
        .await?;

    for relay in relays.iter() {
        println!("{}", relay);
    }

    println!("\n\nConfigure relays...");

    for relay in relays.iter() {
        println!("Configure tor relay {}", relay.name);

        // NOTE: Replace bash script with useradd and template
        let mut command = Command::new("bash");
        command
            .args(["/usr/sbin/tor-instance-create", &relay.name])
            .status()?;

        let conf_file = generate_torrc(relay)?;
        fs::write(
            format!("/etc/tor/instances/{}/torrc", relay.name),
            conf_file,
        )?;
    }

    if skip_net {
        println!("Skip network configuration")
    } else {
        println!("Configure network interfaces...\n");
        // NOTE: the network configuration is not safe to be called multiple time

        // Get tor relay conf
        let node_conf = client
            .get(format!("{}/private/config/resolved/node", server_url))
            .bearer_auth(&session_token)
            .send()
            .await?
            .error_for_status()?
            .json::<NodeConf>()
            .await?;

        let (connection, net_handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);

        let interface_index = find_network_interface(&net_handle).await?;
        set_link_up(&net_handle, interface_index).await?;

        // add default route only after
        add_default_route_v4(node_conf.network.ipv4_gateway.parse()?, &net_handle).await?;
        add_default_route_v6(node_conf.network.ipv6_gateway.parse()?, &net_handle).await?;
    }

    if !is_first_run && !skip_backup {
        println!("Fetch tor keys backup");

        for relay in relays.iter() {
            // Get tor relay conf
            let data: Vec<u8> = client
                .get(format!("{}/private/relays/data/{}", server_url, relay.name))
                .bearer_auth(&session_token)
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?
                .into();

            let archive_bkp = cipher.decrypt(&nonce.into(), data.as_slice()).unwrap();

            println!("Put keys in place");

            let mut archive_bkp = Archive::new(archive_bkp.as_slice());
            archive_bkp.set_overwrite(true);
            archive_bkp.set_preserve_ownerships(true);
            archive_bkp.set_preserve_mtime(true);
            archive_bkp.set_preserve_permissions(true);

            let keys_dir = Path::new(&TOR_INSTANCE_LIB_DIR)
                .join(&relay.name)
                .join("keys");

            archive_bkp.unpack(&keys_dir)?;

            let uid = Passwd::from_name(CString::new(format!("_tor-{}", &relay.name))?)?
                .unwrap()
                .uid;
            let gid = Passwd::from_name(CString::new(format!("_tor-{}", &relay.name))?)?
                .unwrap()
                .gid;

            // Fix permissions on keys directory
            chown(&keys_dir, Some(uid), Some(gid))?;

            for entry in fs::read_dir(&keys_dir)? {
                chown(entry?.path(), Some(uid), Some(gid))?;
            }
        }
    }

    let systemctl = SystemCtl::default();

    println!("\nStart services");

    for relay in relays.iter() {
        let _ = systemctl.start(format!("tor@{}.service", relay.name).as_ref());
    }

    let wait_seconds = 5;
    println!("Wait {} seconds before bakup keys", wait_seconds);

    tokio::time::sleep(Duration::from_secs(wait_seconds)).await;

    for relay in relays.iter() {
        println!("Backup {}", relay.name);
        let archive_bkp = backup_tor_keys(&relay.name)?;

        std::fs::write(format!("./{}", relay.name), &archive_bkp)?;

        let encrypted_bkp = cipher
            .encrypt(&nonce.into(), archive_bkp.as_slice())
            .unwrap();

        let _ = client
            .post(format!("{}/private/relays/data/{}", server_url, relay.name))
            .bearer_auth(&session_token)
            .body(encrypted_bkp)
            .send()
            .await?
            .error_for_status()?;
    }

    Ok(())
}

async fn cmd_tpm(config: TpmCommands, tpm2: Option<String>) -> anyhow::Result<()> {
    let tpm_device_name = match tpm2 {
        Some(device) => TctiNameConf::Device(device.parse()?),
        None => TctiNameConf::from_environment_variable()?,
    };

    let context = &mut Context::new(tpm_device_name)?;

    match config {
        TpmCommands::ListPersistent => {}
        TpmCommands::CleanPersistent => {
            remove_persitent_handle(context, get_persistent_handler());
        }
        TpmCommands::CreatePrimary => {
            create_and_persist(context);
        }
        TpmCommands::Encrypt => {
            let plain_text = "miao miao";
            let cypher_text = encrypt(context, plain_text.as_bytes().to_vec());
            let _ = fs::write("encrypted.txt", cypher_text);
        }
        TpmCommands::Decrypt => {
            let input = fs::read("encrypted.txt").unwrap();
            let plain_text = decrypt(context, input);

            println!(
                "=== Decrypted data ===\n\n{}",
                std::str::from_utf8(&plain_text).unwrap()
            );
        }
        TpmCommands::Test => {
            test_aes_gcm(context);
        }
    }

    Ok(())
}

async fn cmd_net(config: NetCommands) -> anyhow::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    match config {
        NetCommands::Add => {}
        NetCommands::List => {
            let _ = find_network_interface(&handle).await.unwrap();
        }
    }

    Ok(())
}
