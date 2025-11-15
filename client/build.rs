use const_gen::*;
use std::{
    env,
    fs::{self},
    path::Path,
};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("const_gen.rs");

    let ca_file = env::var("PATELA_CA_CERT").unwrap();
    let server_ca = Some(fs::read(ca_file).unwrap());

    let const_declarations = const_declaration!(pub SERVER_CA = server_ca);

    fs::write(&dest_path, const_declarations).unwrap();
}
