use anyhow::{Result, anyhow};
use std::env::{self, VarError};
use std::path::PathBuf;
use std::process::Command;

const K_DIR: &str = "k";
const KO_STEM: &str = "tcm";
const KO_NAME: &str = "tcm.ko";

fn kmod_setup() -> Result<PathBuf> {
    let k = env::current_dir()
        .inspect_err(|e| eprintln!("current_dir failed: {e}"))?
        .join(K_DIR);

    println!("compile k {k:?}");

    let status = Command::new("make").current_dir(&k).status()?;

    if !status.success() {
        return Err(anyhow!("make failed: {status:?}"));
    }

    let ko = k.join("build").join(KO_NAME);
    match ko.exists() {
        true => Ok(ko),
        false => Err(anyhow!("ko file not found: {ko:?}")),
    }
}

fn insmod(ko: &PathBuf) -> Result<()> {
    println!("insmod {ko:?}");
    let status = Command::new("sudo")
        .arg("insmod")
        .arg(ko.as_os_str())
        .status()
        .inspect_err(|e| eprintln!("insmod failed: {e}"))?;

    match status.success() {
        true => {
            println!("insmod {ko:?} success");
            Ok(())
        }
        false => Err(anyhow!("insmod failed: {status:?}")),
    }
}

fn lsmod(name: &str) -> bool {
    let output = match Command::new("lsmod")
        .output()
        .inspect_err(|e| eprintln!("lsmod failed: {e}"))
    {
        Ok(output) => output,
        Err(_) => return false,
    };

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.split_whitespace().next().map_or(false, |n| n == name) {
            return true;
        }
    }

    false
}

fn kmod_cleanup(name: &str) -> Result<()> {
    println!("rmmod {name}");
    let status = Command::new("sudo").arg("rmmod").arg(name).status()?;
    match status.success() {
        true => {
            println!("rmmod {name} success");
            Ok(())
        }
        false => Err(anyhow!("rmmod failed: {status:?}")),
    }
}

fn lauch_k() -> Result<()> {
    match env::var("AUTO_LAUNCH_TCM") {
        Ok(v) => {
            let v = v.to_lowercase();
            if !matches!(v.as_str(), "true" | "1") {
                println!("AUTO_LAUNCH_TCM={v}, is not 'true' or '1', disabled");
                return Ok(());
            }
            println!("AUTO_LAUNCH_TCM={v}, enabled");
        }
        Err(VarError::NotPresent) => {
            println!("AUTO_LAUNCH_TCM is not set, disabled");
            return Ok(());
        }
        Err(VarError::NotUnicode(e)) => {
            eprintln!("AUTO_LAUNCH_TCM={e:?}, not unicode, disabled");
            return Ok(());
        }
    };
    if lsmod(KO_STEM) {
        kmod_cleanup(KO_STEM).inspect_err(|e| eprintln!("rmmod failed: {e}"))?;
    }
    let ko = kmod_setup().inspect_err(|e| eprintln!("kmod setup failed: {e}"))?;
    insmod(&ko).inspect_err(|e| eprintln!("insmod failed: {e}"))?;
    Ok(())
}

fn main() -> Result<()> {
    lauch_k()?;
    Ok(())
}
