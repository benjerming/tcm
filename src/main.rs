mod app;
mod netlink;
mod tcm;
mod undo;

use crate::app::App;
use crate::netlink::*;
use crate::tcm::*;
use anyhow::{Context, Result};
use genetlink::new_connection;
use log::{debug, error, info, warn};
use netlink_proto::sys::AsyncSocket;
use std::sync::Arc;

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
    let auth_key = std::env::var("TCM_AUTH_KEY").unwrap_or_else(|_| {
        warn!("TCM_AUTH_KEY 未设置，将使用默认测试密钥");
        "1234567890".to_owned()
    });

    info!("logging in to TCM");
    client.login(&auth_key).await.context("failed to login")?;
    info!("  success");

    let mut app = App::new(client, listener, handler);
    app.run().await?;

    let listener = app.into_listener();
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
