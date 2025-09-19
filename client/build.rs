use const_gen::*;
use std::{
    env,
    fs::{self},
    path::Path,
};

fn main() {
    println!("cargo::rerun-if-changed=templates/torrc");
    println!("cargo::rerun-if-env-changed=PATELA_CLIENT_CERT");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let server_ca_file = env::var("PATELA_CA_CERT").unwrap();
    let client_key_cert_file = env::var("PATELA_CLIENT_CERT").unwrap();
    let patela_server = env::var("PATELA_SERVER").unwrap();

    let torrc_file = "templates/torrc";

    let server_ca = fs::read(server_ca_file).unwrap();
    let client = fs::read(client_key_cert_file).unwrap();
    let torrc = fs::read_to_string(torrc_file).unwrap();

    let const_declarations = [
        const_declaration!(pub PATELA_SERVER = patela_server),
        const_declaration!(pub SERVER_CA = server_ca),
        const_declaration!(pub CLIENT_KEY_CERT = client),
        const_declaration!(pub TORRC_TEMLPLATE = torrc),
    ]
    .join("\n");

    fs::write(&dest_path, const_declarations).unwrap();
}
