use std::{
    ffi::CString,
    fmt::format,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
    str::FromStr,
    time::Duration,
};

use clap::Parser;
use clap::clap_derive::Subcommand;
use etc_passwd::Passwd;
use ipnetwork::{Ipv4Network, Ipv6Network};
use patela_client::{api::build_client, tpm::*, *};
use patela_server::{TorRelayConf, api::ApiNodeCreateResponse};
use systemctl::SystemCtl;
use tokio::time::sleep;
use tss_esapi::{Context, TctiNameConf, handles::KeyHandle, tcti_ldr::DeviceConfig};

#[derive(Subcommand, Debug, Clone)]
enum NetCommands {
    List,
    Add,
}

#[derive(Subcommand, Debug, Clone)]
enum TpmCommands {
    ListPersistent,
    CleanPersistent,
    CreatePrimary,
    Encrypt,
    Decrypt,
}

#[derive(Subcommand, Debug, Clone)]
enum Commands {
    Start {
        #[arg(long, short, action, help = "Do not run network setup")]
        skip_net: bool,
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

    match config.cmd.unwrap_or(Commands::Start { skip_net: false }) {
        Commands::Start { skip_net } => cmd_start(config.server, config.tpm2, skip_net).await,
        Commands::Tpm { cmd } => cmd_tpm(cmd).await,
        Commands::Net { cmd } => cmd_net(cmd).await,
    }
}

// Yes this is big, but that's life
async fn cmd_start(server_url: String, tpm2: Option<String>, skip_net: bool) -> anyhow::Result<()> {
    let tpm_device_name = match tpm2 {
        Some(device) => TctiNameConf::Device(DeviceConfig::from_str(&device)?),
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
        let node = client
            .post(format!("{}/public/create", server_url))
            .send()
            .await?
            .json::<ApiNodeCreateResponse>()
            .await?;

        println!("Create new node on the server with id {}", node.id);
    }

    // Authenticate with server
    let session_token = client
        .get(format!("{}/public/auth", server_url))
        .send()
        .await?
        .text()
        .await?;

    println!("Succesfuly authenticathed with server");

    // Configuration are send in any case
    let specs = collect_specs()?;

    println!("Push collected specs {:?}\n", specs);

    // Get system configuration in response of hw specs
    let _system_conf = client
        .post(format!("{}/private/specs", server_url))
        .bearer_auth(&session_token)
        .json(&specs)
        .send()
        //.await? // TODO: ssh keys
        //.json::<ApiNodeSpecsResponse>()
        .await?;

    println!("Fetch relays conf");

    // Get tor relay conf
    let relays = client
        .get(format!("{}/private/relays", server_url))
        .bearer_auth(&session_token)
        .send()
        .await?
        .json::<Vec<TorRelayConf>>()
        .await?;

    for relay in relays.iter() {
        println!("{}", relay);
    }

    println!("Configure relays...\n");

    for relay in relays.iter() {
        println!("Configure tor relay {}", relay.name);

        // NOTE: Replace bash script with useradd and template
        let mut command = Command::new("bash");
        command
            .args(["/usr/sbin/tor-instance-create", &relay.name])
            .status()?;

        let conf_file = generate_torrc(&relay)?;
        fs::write(
            format!("/etc/tor/instances/{}/torrc", relay.name),
            conf_file,
        )?;
    }

    if skip_net {
        println!("Skip network configuration")
    } else {
        println!("Configure network interfaces...\n");

        let (connection, net_handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let interface_index = find_network_interface(&net_handle).await?;

        for relay in relays.iter() {
            // TODO: remove hardcoded previx
            add_network_address(
                interface_index,
                Ipv4Network::new(Ipv4Addr::from_str(&relay.or_address_v4)?, 24)?.into(),
                &net_handle,
            )
            .await?;
            add_network_address(
                interface_index,
                Ipv6Network::new(Ipv6Addr::from_str(&relay.or_address_v6)?, 48)?.into(),
                &net_handle,
            )
            .await?;

            let pid = Passwd::from_name(CString::new(format!("_tor-{}", &relay.name)).unwrap())
                .unwrap()
                .unwrap()
                .uid;

            println!("Configure source ips for pid {}:", relay.name);
            println!("\t{}:", relay.or_address_v4);
            println!("\t{}:", relay.or_address_v6);

            set_source_ip_by_process(
                interface_index,
                pid,
                Ipv4Addr::from_str(relay.or_address_v4.as_ref())?,
                Ipv6Addr::from_str(relay.or_address_v6.as_ref())?,
            )?;
        }
    }

    if !is_first_run {
        println!("Fetch tor keys backup");

        for relay in relays.iter() {
            // Get tor relay conf
            let data = client
                .get(format!("{}/private/relays/data/{}", server_url, relay.name))
                .bearer_auth(&session_token)
                .send()
                .await?
                .json::<Vec<u8>>()
                .await?;

            let _relay_bkp = decrypt(context, data);

            println!("Put keys in place");

            // TODO:
        }
    }

    let systemctl = SystemCtl::default();

    println!("Start services");

    for relay in relays.iter() {
        let _ = systemctl.start(format!("tor@{}.service", relay.name).as_ref());
    }

    let wait_seconds = 5;
    println!("Wait {} seconds before bakup keys", wait_seconds);

    sleep(Duration::from_secs(wait_seconds)).await;

    for relay in relays.iter() {
        let blob_bkp = backup_tor_keys(&relay.name)?;
        let encrypted_bkp = encrypt(context, blob_bkp);

        let _ = client
            .post(format!("{}/relays/data/{}", server_url, relay.name))
            .bearer_auth(&session_token)
            .body(encrypted_bkp)
            .send()
            .await?;
    }

    Ok(())
}

async fn cmd_tpm(config: TpmCommands) -> anyhow::Result<()> {
    let context = &mut Context::new(TctiNameConf::from_environment_variable().unwrap()).unwrap();

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
    }

    Ok(())
}

async fn cmd_net(config: NetCommands) -> anyhow::Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
    tokio::spawn(connection);

    match config {
        NetCommands::List => {
            let _ = find_network_interface(&handle).await.unwrap();
        }
        NetCommands::Add => {}
    }

    Ok(())
}
