use anyhow::{Context, Result, anyhow};
use std::env;
use std::path::PathBuf;

fn generate_bindings() -> Result<()> {
    let header = PathBuf::from("k/api/include/tcm/api.h");
    println!("cargo:rerun-if-changed={header:?}");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .allowlist_type("tcm_genl_.*")
        .allowlist_var("TCM_GENL_.*")
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .generate()
        .map_err(|_| anyhow!("failed to generate bindings from {header:?}"))?;

    bindings
        .write_to_file(out_dir.join("tcm_api.rs"))
        .context("failed to write generated bindings")?;

    Ok(())
}

fn main() -> Result<()> {
    generate_bindings()?;
    Ok(())
}
