mod netlink;
mod tcm;
mod undo;

use crate::netlink::*;
use crate::tcm::*;
use crate::undo::*;
use anyhow::{Context, Result, anyhow};
use genetlink::new_connection;
use log::{debug, error, info, warn};
use netlink_proto::sys::AsyncSocket;
use std::path::{Component, Path};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, stdin, stdout};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    info!("resolving family info for TCM");
    let family: crate::netlink::TcmFamilyInfo =
        resolve_family_info(genl_family_name(), genl_family_version(), genl_mcgrp_name()).await?;
    debug!("  resolved family info: {family:?}");

    let (mut conn, handle, receiver) =
        new_connection().context("failed to create generic netlink connection")?;

    let mcgrp = genl_mcgrp_name();
    info!("joining multicast group {mcgrp}");
    conn.socket_mut()
        .socket_mut()
        .add_membership(family.gid)
        .with_context(|| format!("failed to join multicast group {mcgrp}"))?;
    debug!("  joined multicast group {mcgrp}");

    let conn_task = tokio::spawn(async move {
        info!("tokio spawn: receiving netlink messages");
        conn.await;
        info!("tokio spawn: finished receiving netlink messages");
    });

    info!("resolving TCM family id");
    let resolved_family_id = handle
        .resolve_family_id::<TcmPayload>()
        .await
        .context("failed to resolve TCM family id")?;
    debug!("  resolved family id: {resolved_family_id}");

    if family.family_id != resolved_family_id {
        error!(
            "warning: nlctrl reported family id {family:?} but resolver returned {resolved_family_id}",
        );
        return Err(anyhow::anyhow!(
            "TCM family id mismatch: nlctrl reported {family:?} but resolver returned {resolved_family_id}"
        ));
    }

    info!("ready: family info: {family:?}");

    let handler: Arc<dyn TcmEventHandler> = Arc::new(LoggingEventHandler);
    let listener = TcmGenlBroadcastListener::spawn(receiver, {
        let handler = Arc::clone(&handler);
        move |msg| {
            handle_raw_message(msg, handler.as_ref());
        }
    });
    info!("kernel broadcast listener initialized (开启监听，但默认禁用回调)");

    let mut client = TcmGenlClient::new(handle, family.family_id);
    let mut stdin = BufReader::new(stdin());
    let mut stdout = stdout();
    let mut input = String::new();
    let mut undo_redo = UndoRedoManager::new();
    let auth_key = std::env::var("TCM_AUTH_KEY").unwrap_or_else(|_| {
        warn!("TCM_AUTH_KEY 未设置，将使用默认测试密钥");
        "1234567890".to_owned()
    });

    info!("logging in to TCM");
    client.login(&auth_key).await.context("failed to login")?;
    info!("  success");

    loop {
        stdout.write_all("\n".as_bytes()).await?;
        stdout.write_all("请选择工作模式:\n".as_bytes()).await?;
        stdout.write_all("1. 统计文件监控信息\n".as_bytes()).await?;
        stdout.write_all("2. 接收内核广播消息".as_bytes()).await?;
        stdout.write_all("   CTRL+C 返回菜单\n".as_bytes()).await?;
        stdout.write_all("3. 添加信任文件[夹]\n".as_bytes()).await?;
        stdout.write_all("4. 移除信任文件[夹]\n".as_bytes()).await?;
        stdout.write_all("5. 添加信任进程[组]\n".as_bytes()).await?;
        stdout.write_all("6. 移除信任进程[组]\n".as_bytes()).await?;
        stdout.write_all("7. 撤销上一次操作\n".as_bytes()).await?;
        stdout.write_all("8. 重做上一次撤销\n".as_bytes()).await?;
        stdout.write_all("9. 打印撤销/重做栈\n".as_bytes()).await?;
        stdout.write_all("q. 退出程序\n".as_bytes()).await?;
        stdout.write_all("> ".as_bytes()).await?;
        stdout.flush().await?;

        input.clear();
        let bytes = stdin.read_line(&mut input).await?;
        if bytes == 0 {
            info!("标准输入已关闭，准备退出");
            break;
        }

        match input.trim() {
            "1" => {
                info!("requesting file listener stats via Generic Netlink");
                match client.get_file_monitor_stats().await {
                    Ok(stats) => {
                        info!("received on-demand file stats response");
                        handler.on_file_stats(stats);
                    }
                    Err(err) => {
                        warn!("failed to request file stats: {err:?}");
                    }
                }
            }
            "2" => {
                listener.enable();

                match signal::ctrl_c().await {
                    Ok(()) => {
                        stdout.write_all("\nCTRL + C\n".as_bytes()).await?;
                    }
                    Err(err) => {
                        stdout
                            .write_all(format!("\n错误: {err:?}\n").as_bytes())
                            .await?;
                    }
                }

                listener.disable();
            }
            "3" => {
                let path =
                    match prompt_path(&mut stdout, &mut stdin, "请输入信任文件[夹](以/结尾): ")
                        .await?
                    {
                        Some(path) => path,
                        None => {
                            info!("标准输入已关闭，准备退出");
                            break;
                        }
                    };

                match client.put_trust_path(&path).await {
                    Ok(()) => {
                        undo_redo.record(TrustAction::TrustFileAdd(path.clone()));
                        stdout.write_all("信任文件[夹]已更新\n".as_bytes()).await?;
                    }
                    Err(err) => {
                        warn!("添加信任文件[夹]失败: {err:?}");
                        stdout
                            .write_all(format!("错误: {err:?}\n").as_bytes())
                            .await?;
                    }
                }
            }
            "4" => {
                let path = match prompt_path(
                    &mut stdout,
                    &mut stdin,
                    "请输入要移除的信任文件[夹](以/结尾): ",
                )
                .await?
                {
                    Some(path) => path,
                    None => {
                        info!("标准输入已关闭，准备退出");
                        break;
                    }
                };

                match client.distrust_path(&path).await {
                    Ok(()) => {
                        undo_redo.record(TrustAction::TrustFileRemove(path.clone()));
                        stdout.write_all("信任文件[夹]已更新\n".as_bytes()).await?;
                    }
                    Err(err) => {
                        warn!("移除信任文件[夹]失败: {err:?}");
                        stdout
                            .write_all(format!("错误: {err:?}\n").as_bytes())
                            .await?;
                    }
                }
            }
            "5" => {
                let pid = match prompt_pid(
                    &mut stdout,
                    &mut stdin,
                    "请输入要添加信任的进程 PID(负数表示单个进程，正数表示进程树): ",
                )
                .await?
                {
                    Some(result) => result,
                    None => {
                        info!("标准输入已关闭，准备退出");
                        break;
                    }
                };

                match client.put_trust_proc_list(vec![pid]).await {
                    Ok(()) => {
                        undo_redo.record(TrustAction::TrustProcAdd(pid));
                        stdout.write_all("信任进程[组]已更新\n".as_bytes()).await?;
                    }
                    Err(err) => {
                        warn!("添加信任进程[组]失败: {err:?}");
                        stdout
                            .write_all(format!("错误: {err:?}\n").as_bytes())
                            .await?;
                    }
                }
            }
            "6" => {
                let pid = match prompt_pid(
                    &mut stdout,
                    &mut stdin,
                    "请输入要移除的进程 PID(负数表示单个进程，正数表示进程树): ",
                )
                .await?
                {
                    Some(result) => result,
                    None => {
                        info!("标准输入已关闭，准备退出");
                        break;
                    }
                };

                match client.distrust_proc(pid).await {
                    Ok(()) => {
                        stdout.write_all("信任进程[组]已更新\n".as_bytes()).await?;
                        undo_redo.record(TrustAction::TrustProcRemove(pid));
                    }
                    Err(err) => {
                        warn!("移除信任进程[组]失败: {err:?}");
                        stdout
                            .write_all(format!("错误: {err:?}\n").as_bytes())
                            .await?;
                    }
                }
            }
            "7" => match undo_redo.undo(&mut client).await {
                Ok(action) => {
                    let msg = format!("已撤销: {}\n", action.describe());
                    stdout.write_all(msg.as_bytes()).await?;
                }
                Err(err) => {
                    stdout
                        .write_all(format!("错误: {err:?}\n").as_bytes())
                        .await?;
                }
            },
            "8" => match undo_redo.redo(&mut client).await {
                Ok(action) => {
                    let msg = format!("已重做: {}\n", action.describe());
                    stdout.write_all(msg.as_bytes()).await?;
                }
                Err(err) => {
                    stdout
                        .write_all(format!("错误: {err:?}\n").as_bytes())
                        .await?;
                }
            },
            "9" => {
                let (undo_stack, redo_stack) = undo_redo.stack_descriptions();
                let mut message = String::from("\n撤销栈 (栈顶在上):\n");
                if undo_stack.is_empty() {
                    message.push_str("  <空>\n");
                } else {
                    for (idx, entry) in undo_stack.iter().enumerate() {
                        message.push_str(&format!("  {}. {}\n", idx + 1, entry));
                    }
                }
                message.push_str("重做栈 (栈顶在上):\n");
                if redo_stack.is_empty() {
                    message.push_str("  <空>\n");
                } else {
                    for (idx, entry) in redo_stack.iter().enumerate() {
                        message.push_str(&format!("  {}. {}\n", idx + 1, entry));
                    }
                }
                stdout.write_all(message.as_bytes()).await?;
            }
            "q" | "Q" => {
                info!("用户选择退出程序");
                break;
            }
            "" => {
                continue;
            }
            _ => {
                stdout.write_all("无效输入\n".as_bytes()).await?;
                continue;
            }
        }
    }

    listener.shutdown().await;
    conn_task.abort();
    let _ = conn_task.await;

    info!("userspace listener terminated");
    Ok(())
}

struct LoggingEventHandler;

impl TcmEventHandler for LoggingEventHandler {
    fn on_proc(&self, event: TcmProcEvent) {
        info!("{event:?}");
    }

    fn on_file(&self, event: TcmFileEvent) {
        info!("{event:?}");
    }

    fn on_file_stats(&self, event: TcmFileMonitorStats) {
        info!(
            "file stats: pid_table_size={} pid_entries={} file_entries={} top_pid_count={}",
            event.pid_table_size,
            event.pid_entry_count,
            event.file_entry_count,
            event.top_pid_count
        );

        if event.top_pids.is_empty() {
            info!("  no processes tracked");
            return;
        }

        for (idx, stat) in event.top_pids.iter().enumerate() {
            info!(
                "  top #{idx}: pid={} file_count={}",
                stat.pid, stat.file_count
            );
        }
    }
}

async fn prompt_line(
    stdout: &mut tokio::io::Stdout,
    stdin: &mut BufReader<tokio::io::Stdin>,
    prompt: &str,
) -> Result<Option<String>> {
    stdout.write_all(prompt.as_bytes()).await?;
    stdout.flush().await?;

    let mut buf = String::new();
    let bytes = stdin.read_line(&mut buf).await?;
    if bytes == 0 {
        return Ok(None);
    }

    Ok(Some(buf.trim().to_owned()))
}

async fn prompt_path(
    stdout: &mut tokio::io::Stdout,
    stdin: &mut BufReader<tokio::io::Stdin>,
    prompt: &str,
) -> Result<Option<String>> {
    loop {
        match prompt_line(stdout, stdin, prompt).await? {
            None => return Ok(None),
            Some(input) => match normalize_path(&input) {
                Ok(path) => return Ok(Some(path)),
                Err(err) => {
                    stdout
                        .write_all(format!("错误: {err}\n").as_bytes())
                        .await?;
                }
            },
        }
    }
}

async fn prompt_pid(
    stdout: &mut tokio::io::Stdout,
    stdin: &mut BufReader<tokio::io::Stdin>,
    prompt: &str,
) -> Result<Option<i32>> {
    loop {
        match prompt_line(stdout, stdin, prompt).await? {
            None => return Ok(None),
            Some(input) if input.is_empty() => {
                stdout.write_all("PID 不能为空\n".as_bytes()).await?;
            }
            Some(input) => match input.parse::<i32>() {
                Ok(pid) if pid != 0 => {
                    return Ok(Some(pid));
                }
                _ => {
                    stdout.write_all("PID 无效\n".as_bytes()).await?;
                }
            },
        }
    }
}

fn normalize_path(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("路径不能为空"));
    }

    let has_trailing_slash = trimmed.ends_with('/');
    let path = Path::new(trimmed);
    let mut normalized_segments: Vec<String> = Vec::new();
    let mut is_absolute = path.is_absolute();

    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(anyhow!("不支持包含磁盘前缀的路径"));
            }
            Component::RootDir => {
                is_absolute = true;
                normalized_segments.clear();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized_segments.pop().is_none() {
                    if !is_absolute {
                        return Err(anyhow!("路径越界: 包含无法解析的 .."));
                    }
                }
            }
            Component::Normal(segment) => {
                let segment_str = segment.to_string_lossy();
                if segment_str.is_empty() {
                    continue;
                }
                normalized_segments.push(segment_str.into_owned());
            }
        }
    }

    let mut normalized = String::new();
    if is_absolute {
        normalized.push('/');
    }
    normalized.push_str(&normalized_segments.join("/"));

    if normalized.is_empty() {
        normalized = if is_absolute { "/".into() } else { ".".into() };
    }

    if has_trailing_slash && !normalized.ends_with('/') {
        normalized.push('/');
    }

    Ok(normalized)
}
