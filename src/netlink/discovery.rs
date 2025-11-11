use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::new_connection;
use netlink_packet_core::{NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::{
    GenlMessage,
    ctrl::nlas::{GenlCtrlAttrs, McastGrpAttrs},
    ctrl::{GenlCtrl, GenlCtrlCmd},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmFamilyInfo {
    pub family_id: u16,
    pub gid: u32,
}

pub async fn resolve_family_info(
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
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST;

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
