mod netlink;
mod tcm;

use std::sync::Arc;

use anyhow::{Context, Result};
use genetlink::new_connection;
use log::{debug, error, info, warn};
use netlink_proto::sys::AsyncSocket;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, stdin, stdout};
use tokio::signal;

use crate::netlink::{TcmGenlBroadcastListener, TcmGenlClient, resolve_family_info};
use crate::tcm::{
    TCM_GENL_FAMILY_NAME, TCM_GENL_FAMILY_VERSION, TCM_GENL_MCGRP_NAME, TcmEventHandler,
    TcmExitEvent, TcmFileEvent, TcmFileStats, TcmForkRetEvent, TcmMessage, handle_raw_message,
};

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    info!("resolving family info for TCM");
    let family: crate::netlink::TcmFamilyInfo = resolve_family_info(
        TCM_GENL_FAMILY_NAME,
        TCM_GENL_FAMILY_VERSION,
        TCM_GENL_MCGRP_NAME,
    )
    .await?;
    debug!("  resolved family info: {family:?}");

    let (mut conn, handle, receiver) =
        new_connection().context("failed to create generic netlink connection")?;

    info!("joining multicast group {TCM_GENL_MCGRP_NAME}");
    conn.socket_mut()
        .socket_mut()
        .add_membership(family.gid)
        .with_context(|| format!("failed to join multicast group {TCM_GENL_MCGRP_NAME}"))?;
    debug!("  joined multicast group {TCM_GENL_MCGRP_NAME}");

    let conn_task = tokio::spawn(async move {
        info!("tokio spawn: receiving netlink messages");
        conn.await;
        info!("tokio spawn: finished receiving netlink messages");
    });

    info!("resolving TCM family id");
    let resolved_family_id = handle
        .resolve_family_id::<TcmMessage>()
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

    loop {
        stdout.write_all("\n".as_bytes()).await?;
        stdout.write_all("请选择工作模式:\n".as_bytes()).await?;
        stdout.write_all("1. 获取内核状态\n".as_bytes()).await?;
        stdout
            .write_all("2. 接收内核事件 (Ctrl+C 返回菜单)\n".as_bytes())
            .await?;
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
                match client.request_file_stats().await {
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
                stdout
                    .write_all("\n开始接收内核广播，按 Ctrl+C 返回菜单...\n".as_bytes())
                    .await?;
                stdout.flush().await?;

                match signal::ctrl_c().await {
                    Ok(()) => {
                        info!("CTRL + C received, returning to menu");
                        stdout
                            .write_all("\n已退出广播模式，返回菜单。\n".as_bytes())
                            .await?;
                        stdout.flush().await?;
                    }
                    Err(err) => {
                        warn!("failed to listen for Ctrl+C: {err:?}");
                        stdout
                            .write_all("\n监听 Ctrl+C 失败，返回菜单。\n".as_bytes())
                            .await?;
                        stdout.flush().await?;
                    }
                }

                listener.disable();
            }
            "q" | "Q" => {
                info!("用户选择退出程序");
                break;
            }
            "" => {
                continue;
            }
            _ => {
                stdout
                    .write_all("无效的选择，请重新输入。\n".as_bytes())
                    .await?;
                stdout.flush().await?;
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
    fn on_fork_ret(&self, event: TcmForkRetEvent) {
        info!("{event:?}");
    }

    fn on_file(&self, event: TcmFileEvent) {
        info!("{event:?}");
    }

    fn on_exit(&self, event: TcmExitEvent) {
        info!("{event:?}");
    }

    fn on_file_stats(&self, event: TcmFileStats) {
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
