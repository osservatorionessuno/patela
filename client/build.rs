use const_gen::*;
use std::{
    env,
    fs::{self},
    path::Path,
};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let server_ca = match env::var("PATELA_CA_CERT").ok() {
        Some(ca_file) => fs::read(ca_file).ok(),
        None => None,
    };

    let const_declarations = const_declaration!(pub SERVER_CA = server_ca);

    fs::write(&dest_path, const_declarations).unwrap();
}
