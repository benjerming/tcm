mod tcm;

use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::message::{RawGenlMessage, map_from_rawgenlmsg};
use genetlink::new_connection;
use log::{debug, error, info, warn};
use netlink_packet_core::{NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::{
    GenlMessage,
    ctrl::{
        GenlCtrl, GenlCtrlCmd,
        nlas::{GenlCtrlAttrs, McastGrpAttrs},
    },
};
use netlink_proto::sys::AsyncSocket;
use tokio::signal;

use crate::tcm::{
    TCM_FAMILY_NAME, TCM_FAMILY_VERSION, TCM_MCGRP_NAME, TcmCmd, TcmFileEvent, TcmFileOp,
    TcmForkEvent, TcmForkRetEvent, TcmMessage,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmFamilyInfo {
    pub family_id: u16,
    pub gid: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "debug"));

    info!("resolving family info for TCM");
    let family = resolve_family_info(TCM_FAMILY_NAME, TCM_FAMILY_VERSION, TCM_MCGRP_NAME).await?;
    debug!("  resolved family info: {family:?}");

    let (mut conn, handle, mut messages) =
        new_connection().context("failed to create generic netlink connection")?;

    info!("joining multicast group {TCM_MCGRP_NAME}");
    conn.socket_mut()
        .socket_mut()
        .add_membership(family.gid)
        .with_context(|| format!("failed to join multicast group {TCM_MCGRP_NAME}"))?;
    debug!("  joined multicast group {TCM_MCGRP_NAME}");

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
    info!("waiting for fork events (press Ctrl+C to exit)...");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("CTRL + C received, shutting down...");
                break;
            }
            message = messages.next() => {
                match message {
                    Some((msg, _addr)) => on_raw_message(msg),
                    None => {
                        info!("netlink connection closed by kernel");
                        break;
                    }
                }
            }
        }
    }

    conn_task.abort();
    let _ = conn_task.await;

    info!("userspace listener terminated");
    Ok(())
}

fn on_genl_message(genlmsg: GenlMessage<TcmMessage>) {
    match genlmsg.payload.cmd {
        TcmCmd::ForkEvent => match TcmForkEvent::try_from(genlmsg) {
            Ok(event) => on_fork_event(event),
            Err(err) => {
                warn!("failed to decode fork event: {err:?}");
            }
        },
        TcmCmd::ForkRetEvent => match TcmForkRetEvent::try_from(genlmsg) {
            Ok(event) => on_fork_ret_event(event),
            Err(err) => {
                warn!("failed to decode fork ret event: {err:?}");
            }
        },
        TcmCmd::FileEvent => match TcmFileEvent::try_from(genlmsg) {
            Ok(event) => on_file_event(event),
            Err(err) => {
                warn!("failed to decode file event: {err:?}");
            }
        },
    }
}

fn on_netlink_payload(payload: NetlinkPayload<GenlMessage<TcmMessage>>) {
    match payload {
        NetlinkPayload::InnerMessage(genlmsg) => on_genl_message(genlmsg),
        NetlinkPayload::Error(err) => {
            warn!("received netlink error: {err:?}");
        }
        other => {
            warn!("ignoring non data payload: {other:?}");
        }
    }
}

fn on_netlink_message(decoded: NetlinkMessage<GenlMessage<TcmMessage>>) {
    on_netlink_payload(decoded.payload)
}

fn on_raw_message(msg: NetlinkMessage<RawGenlMessage>) {
    match map_from_rawgenlmsg::<TcmMessage>(msg) {
        Ok(decoded) => on_netlink_message(decoded),
        Err(err) => {
            warn!("failed to decode message: {err:?}");
        }
    }
}

fn on_fork_event(event: TcmForkEvent) {
    info!("{event:?}");
}

fn on_fork_ret_event(event: TcmForkRetEvent) {
    info!("{event:?}");
}

fn on_file_event(event: TcmFileEvent) {
    let op = match event.operation {
        TcmFileOp::Open => "open",
        TcmFileOp::Write => "write",
        TcmFileOp::Close => "close",
    };

    info!(
        "file {op}: pid={} fd={} bytes={} path={}",
        event.pid, event.fd, event.bytes, event.path
    );
}

async fn resolve_family_info(
    family_name: &str,
    version: u8,
    mcgrp_name: &str,
) -> Result<TcmFamilyInfo> {
    let (conn, mut handle, messages) =
        new_connection().context("failed to open netlink connection for discovery")?;
    drop(messages);

    let conn_task = tokio::spawn(async move {
        conn.await;
    });

    let message = {
        let header = {
            let mut header = NetlinkHeader::default();
            header.flags = NLM_F_REQUEST;
            header
        };

        let payload = GenlMessage::from_payload(GenlCtrl {
            cmd: GenlCtrlCmd::GetFamily,
            nlas: vec![
                GenlCtrlAttrs::FamilyName(family_name.to_owned()),
                GenlCtrlAttrs::Version(version as u32),
            ],
        });

        let mut msg = NetlinkMessage::new(header, payload.into());
        msg.finalize();
        msg
    };

    let query_result = async {
        let mut responses = handle
            .request(message)
            .await
            .context(format!("failed to request family info for family={family_name} and version={version}"))?;

        let mut family_id: Option<u16> = None;
        let mut gid: Option<u32> = None;

        while let Some(response) = responses.next().await {
            let packet = response.context("failed to decode discovery response")?;
            match packet.payload {
                NetlinkPayload::InnerMessage(genlmsg) => {
                    if !matches!(
                        genlmsg.payload.cmd,
                        GenlCtrlCmd::GetFamily | GenlCtrlCmd::NewFamily
                    ) {
                        continue;
                    }

                    for nlas in genlmsg.payload.nlas {
                        match nlas {
                            GenlCtrlAttrs::FamilyId(id) => family_id = Some(id),
                            GenlCtrlAttrs::McastGroups(groups) => {
                                for group in groups {
                                    let mut name: Option<String> = None;
                                    let mut id: Option<u32> = None;
                                    for attr in group {
                                        match attr {
                                            McastGrpAttrs::Name(n) => name = Some(n),
                                            McastGrpAttrs::Id(v) => id = Some(v),
                                        }
                                    }

                                    if matches!(name, Some(n) if n == mcgrp_name) {
                                        if let Some(group_id) = id {
                                            gid = Some(group_id);
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                NetlinkPayload::Error(err) => {
                    return Err(anyhow::anyhow!(
                        "netlink payload error while resolving family: {err:?}"
                    ));
                }
                _ => {}
            }
        }

        let family_id = family_id.context(format!(
            "missing family id in response for family={family_name} and version={version}"
        ))?;
        let gid = gid.context(format!(
            "missing multicast group id in response for family={family_name} and version={version} and group={mcgrp_name}"
        ))?;

        Ok((family_id, gid))
    }
    .await;

    conn_task.abort();
    let _ = conn_task.await;

    let (family_id, gid) = query_result?;

    Ok(TcmFamilyInfo { family_id, gid })
}
