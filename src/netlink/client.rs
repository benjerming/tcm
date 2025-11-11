use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::GenetlinkHandle;
use netlink_packet_core::{NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;

use crate::tcm::{TcmAttr, TcmCommand, TcmFileStats, TcmMessage, TcmOp};

pub struct TcmGenlClient {
    handle: GenetlinkHandle,
    family_id: u16,
}

impl TcmGenlClient {
    pub fn new(handle: GenetlinkHandle, family_id: u16) -> Self {
        Self { handle, family_id }
    }

    fn build_message(
        &self,
        cmd: TcmCommand,
        nlas: Vec<TcmAttr>,
    ) -> NetlinkMessage<GenlMessage<TcmMessage>> {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST;
        header.message_type = self.family_id;

        let payload = GenlMessage::from_payload(TcmMessage { cmd, nlas });
        let mut message = NetlinkMessage::new(header, payload.into());
        message.finalize();
        message
    }

    async fn request_raw(
        &mut self,
        cmd: TcmCommand,
        nlas: Vec<TcmAttr>,
    ) -> Result<Vec<GenlMessage<TcmMessage>>> {
        let message = self.build_message(cmd, nlas);

        let mut responses = self
            .handle
            .request(message)
            .await
            .with_context(|| format!("发送 {:?} 请求失败", cmd))?;

        let mut messages = Vec::new();

        while let Some(response) = responses.next().await {
            let packet = response.context("解析 netlink 响应失败")?;
            match packet.payload {
                NetlinkPayload::InnerMessage(genlmsg) => messages.push(genlmsg),
                NetlinkPayload::Error(err) => {
                    return Err(anyhow::anyhow!("内核返回错误响应: {err:?}"));
                }
                other => {
                    log::warn!("忽略非数据 payload: {other:?}");
                }
            }
        }

        Ok(messages)
    }

    async fn request_with<F, T>(
        &mut self,
        cmd: TcmCommand,
        nlas: Vec<TcmAttr>,
        mut parse: F,
    ) -> Result<T>
    where
        F: FnMut(GenlMessage<TcmMessage>) -> Result<Option<T>>,
    {
        let messages = self.request_raw(cmd, nlas).await?;

        for genlmsg in messages {
            match parse(genlmsg) {
                Ok(Some(result)) => return Ok(result),
                Ok(None) => continue,
                Err(err) => {
                    log::warn!("处理 netlink 响应失败: {err:?}");
                }
            }
        }

        Err(anyhow::anyhow!(format!("未收到 {:?} 的预期响应", cmd)))
    }

    #[allow(dead_code)]
    pub async fn request_operation_raw(
        &mut self,
        op: TcmOp,
        nlas: Vec<TcmAttr>,
    ) -> Result<Vec<GenlMessage<TcmMessage>>> {
        self.request_raw(TcmCommand::Operation(op), nlas)
            .await
            .with_context(|| format!("处理 {:?} 操作失败", op))
    }

    pub async fn request_operation<F, T>(
        &mut self,
        op: TcmOp,
        nlas: Vec<TcmAttr>,
        parse: F,
    ) -> Result<T>
    where
        F: FnMut(GenlMessage<TcmMessage>) -> Result<Option<T>>,
    {
        self.request_with(TcmCommand::Operation(op), nlas, parse)
            .await
            .with_context(|| format!("处理 {:?} 操作失败", op))
    }

    /// 主动请求内核文件统计信息，并返回解析后的结果。
    pub async fn request_file_stats(&mut self) -> Result<TcmFileStats> {
        self.request_operation(TcmOp::GetFileStats, Vec::new(), |genlmsg| {
            match TcmFileStats::try_from(genlmsg) {
                Ok(stats) => Ok(Some(stats)),
                Err(err) => {
                    log::warn!("忽略无法解析的文件统计响应: {err:?}");
                    Ok(None)
                }
            }
        })
        .await
    }
}
