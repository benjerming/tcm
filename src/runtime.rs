use crate::netlink::{TcmGenlBroadcastListener, TcmGenlClient, resolve_family_info};
use crate::tcm::{
    TcmEventHandler, genl_family_name, genl_family_version, genl_mcgrp_name, handle_raw_message,
};
use anyhow::{Context, Result};
use genetlink::new_connection;
use log::{debug, error, info};
use netlink_proto::sys::AsyncSocket;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub struct RuntimeGuard {
    conn_task: JoinHandle<()>,
}

impl RuntimeGuard {
    pub async fn shutdown(self, listener: TcmGenlBroadcastListener) {
        listener.shutdown().await;
        self.conn_task.abort();
        match self.conn_task.await {
            Ok(()) => info!("netlink connection task finished"),
            Err(err) if err.is_cancelled() => {
                debug!("netlink connection task cancelled as part of shutdown");
            }
            Err(err) => {
                error!("netlink connection task join error: {err:?}");
            }
        }
    }
}

pub struct RuntimeBootstrap {
    pub guard: RuntimeGuard,
    pub client: TcmGenlClient,
    pub listener: TcmGenlBroadcastListener,
}

pub async fn bootstrap(handler: Arc<dyn TcmEventHandler>) -> Result<RuntimeBootstrap> {
    info!("resolving family info for TCM");
    let family =
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
        .resolve_family_id::<crate::tcm::TcmPayload>()
        .await
        .context("failed to resolve TCM family id")?;
    debug!("  resolved family id: {resolved_family_id}");

    if family.family_id != resolved_family_id {
        return Err(anyhow::anyhow!(
            "TCM family id mismatch: nlctrl reported {family:?} but resolver returned {resolved_family_id}"
        ));
    }

    info!("ready: family info: {family:?}");

    let listener = TcmGenlBroadcastListener::spawn(receiver, {
        let handler = Arc::clone(&handler);
        move |msg| {
            handle_raw_message(msg, handler.as_ref());
        }
    });
    info!("kernel broadcast listener initialized (开启监听，但默认禁用回调)");

    let client = TcmGenlClient::new(handle, family.family_id);
    let guard = RuntimeGuard { conn_task };

    Ok(RuntimeBootstrap {
        guard,
        client,
        listener,
    })
}
