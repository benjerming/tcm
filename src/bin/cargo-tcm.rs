use anyhow::{Context, Result, anyhow, bail};
use std::env;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const K_DIR: &str = "k";
const KO_STEM: &str = "tcm";
const KO_NAME: &str = "tcm.ko";

fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let mut args = env::args().skip(1);
    let Some(cmd) = args.next() else {
        return print_help();
    };

    match cmd.as_str() {
        "b" | "build" => {
            let _ = build_kernel_module()?;
        }
        "c" | "clean" => {
            clean_kernel_module()?;
        }
        "l" | "load" => {
            let mut rebuild = true;
            let mut force = false;
            for arg in args {
                match arg.as_str() {
                    "--skip-build" => rebuild = false,
                    "--force" => force = true,
                    _ => bail!("未知参数: {arg}"),
                }
            }
            load_kernel_module(rebuild, force)?;
        }
        "r" | "reload" => {
            unload_kernel_module()?;
            clean_kernel_module()?;
            let _ = build_kernel_module()?;
            load_kernel_module(true, false)?;
        }
        "s" | "status" => {
            if module_loaded()? {
                println!("ℹ️  模块 {KO_STEM} 已加载");
            } else {
                println!("ℹ️  模块 {KO_STEM} 未加载");
            }
        }
        "u" | "unload" => {
            unload_kernel_module().with_context(|| "卸载 kmod 失败")?;
        }
        "-h" | "--help" | "h" | "help" => {
            return print_help();
        }
        other => bail!("未知子命令: {other}"),
    }

    Ok(())
}

fn print_help() -> Result<()> {
    println!(
        "\
用法: cargo tcm <命令> [选项]

命令:
  c, clean             清理 k/ 下的内核模块
  b, build             编译 k/ 下的内核模块
  l, load              编译并加载内核模块 (支持 --skip-build, --force)
  r, reload            卸载并重新编译安装内核模块
  s, status            查看模块是否已加载
  u, unload            卸载内核模块
  h, help              打印本帮助
"
    );
    Ok(())
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn kernel_dir() -> PathBuf {
    project_root().join(K_DIR)
}

fn kernel_build_dir() -> PathBuf {
    kernel_dir().join("build")
}

fn kernel_image_path() -> PathBuf {
    kernel_build_dir().join(KO_NAME)
}

fn clean_kernel_module() -> Result<()> {
    let k = kernel_dir();
    println!("🧹  开始清理内核模块: {k:?}");
    let status = Command::new("make")
        .current_dir(&k)
        .arg("clean")
        .status()
        .context("执行 make clean 失败")?;
    if !status.success() {
        return Err(anyhow!("make clean 失败: {status:?}"));
    }
    println!("✅ 已清理内核模块");
    Ok(())
}

fn build_kernel_module() -> Result<PathBuf> {
    let k = kernel_dir();
    println!("🛠️  开始编译内核模块: {k:?}");
    let status = Command::new("make")
        .current_dir(&k)
        .status()
        .context("执行 make 失败")?;

    if !status.success() {
        return Err(anyhow!("make 失败: {status:?}"));
    }

    let ko = kernel_image_path();
    if !ko.exists() {
        return Err(anyhow!("未找到目标内核模块: {ko:?}"));
    }

    println!("✅ 已编译内核模块: {ko:?}");
    Ok(ko)
}

fn load_kernel_module(rebuild: bool, force: bool) -> Result<()> {
    if module_loaded()? {
        if force {
            println!("模块已加载，正在尝试强制卸载...");
            unload_kernel_module()?;
        } else {
            bail!("模块 {KO_STEM} 已加载。使用 --force 先卸载，或运行 cargo tcm unload");
        }
    }

    let ko = if rebuild {
        build_kernel_module()?
    } else {
        let path = kernel_image_path();
        if !path.exists() {
            bail!("未找到 {path:?}，请先运行 `cargo tcm build` 或删除 --skip-build");
        }
        path
    };

    insmod(&ko)?;
    println!("✅ 已加载模块 {KO_STEM}");
    Ok(())
}

fn unload_kernel_module() -> Result<()> {
    if !module_loaded()? {
        println!("模块 {KO_STEM} 未加载，跳过卸载");
        return Ok(());
    }

    run_sudo_command("rmmod", &[OsStr::new(KO_STEM)])?;
    println!("✅ 已卸载模块 {KO_STEM}");
    Ok(())
}

fn module_loaded() -> Result<bool> {
    let output = Command::new("lsmod")
        .stdout(Stdio::piped())
        .output()
        .context("执行 lsmod 失败")?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line
            .split_whitespace()
            .next()
            .map_or(false, |n| n == KO_STEM)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn insmod(ko: &Path) -> Result<()> {
    run_sudo_command("insmod", &[ko.as_os_str()])?;
    Ok(())
}

fn run_sudo_command(cmd: &str, args: &[&OsStr]) -> Result<()> {
    let mut command = Command::new("sudo");
    command.arg(cmd);
    for arg in args {
        command.arg(arg);
    }

    let status = command
        .status()
        .with_context(|| format!("执行 sudo {cmd} 失败"))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("sudo {cmd} 退出码异常: {status:?}"))
    }
}
