use anyhow::{Context, Result};
use futures::StreamExt;
use genetlink::GenetlinkHandle;
use netlink_packet_core::{
    NLM_F_ACK, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_generic::GenlMessage;

use crate::tcm::{TcmAttr, TcmCommand, TcmFileStats, TcmPayload, TcmOperateCmd};

pub struct TcmGenlClient {
    handle: GenetlinkHandle,
    family_id: u16,
}

impl TcmGenlClient {
    pub fn new(handle: GenetlinkHandle, family_id: u16) -> Self {
        Self { handle, family_id }
    }

    /// 构建 netlink 消息。
    fn build_nl_message(
        &self,
        cmd: TcmCommand,
        nlas: Vec<TcmAttr>,
    ) -> NetlinkMessage<GenlMessage<TcmPayload>> {
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_ACK;
        header.message_type = self.family_id;

        let payload = GenlMessage::from_payload(TcmPayload { cmd, nlas });
        let mut message = NetlinkMessage::new(header, payload.into());
        message.finalize();
        message
    }

    /// 发送 netlink 请求并尝试接收响应。
    async fn request(
        &mut self,
        cmd: TcmCommand,
        nlas: Vec<TcmAttr>,
    ) -> Result<Vec<GenlMessage<TcmPayload>>> {
        let req_nl_msg = self.build_nl_message(cmd, nlas);

        let mut response_stream = self
            .handle
            .request(req_nl_msg)
            .await
            .with_context(|| format!("{cmd:?} 发送请求失败"))?;

        let mut genl_msgs: Vec<GenlMessage<TcmPayload>> = Vec::new();

        while let Some(resp_nl_msg_result) = response_stream.next().await {
            let resp_nl_msg = resp_nl_msg_result
                .with_context(|| format!("{cmd:?} 解码响应信息为TcmMessage失败"))?;
            match resp_nl_msg.payload {
                NetlinkPayload::InnerMessage(genl_msg) => {
                    genl_msgs.push(genl_msg);
                }
                NetlinkPayload::Error(err) => {
                    match err.code {
                        None => {
                            // ACK 表示请求已成功处理，不再有后续数据。
                            break;
                        }
                        Some(code) => {
                            return Err(anyhow::anyhow!("内核返回错误值: {code}"));
                        }
                    }
                }
                other => {
                    log::warn!("忽略非数据 payload: {other:?}");
                }
            }
        }

        Ok(genl_msgs)
    }

    /// 发送 netlink 请求并解析响应（返回解析结果或错误）。
    async fn get<F, T>(&mut self, cmd: TcmCommand, nlas: Vec<TcmAttr>, mut parse: F) -> Result<T>
    where
        F: FnMut(GenlMessage<TcmPayload>) -> Result<T>,
    {
        let messages = self.request(cmd, nlas).await?;

        let n = messages.len();
        for genl_msg in messages {
            match parse(genl_msg) {
                Ok(result) => return Ok(result),
                Err(err) => {
                    log::warn!("{cmd:?} 解析响应失败: {err:?}");
                }
            }
        }

        Err(anyhow::anyhow!("{cmd:?} 收到内核{n}条响应，但均解析失败"))
    }

    /// 发送 netlink 请求并返回原始消息列表（不解析）。
    #[allow(dead_code)]
    pub async fn put(
        &mut self,
        op: TcmOperateCmd,
        nlas: Vec<TcmAttr>,
    ) -> Result<Vec<GenlMessage<TcmPayload>>> {
        self.request(TcmCommand::Operation(op), nlas).await
    }

    /// 发送 netlink 请求并返回原始消息列表（不解析）。
    #[allow(dead_code)]
    pub async fn delete(
        &mut self,
        op: TcmOperateCmd,
        nlas: Vec<TcmAttr>,
    ) -> Result<Vec<GenlMessage<TcmPayload>>> {
        self.request(TcmCommand::Operation(op), nlas).await
    }

    pub async fn get_file_monitor_stats(&mut self) -> Result<TcmFileStats> {
        self.get(
            TcmCommand::Operation(TcmOperateCmd::GetFileStats),
            Vec::new(),
            |genl_msg| TcmFileStats::try_from(genl_msg).context("解析GenlMessage->TcmFileStats"),
        )
        .await
    }

    pub async fn put_file_whitelist(&mut self, path: &str) -> Result<()> {
        let mut nlas = Vec::with_capacity(2);
        nlas.push(TcmAttr::FileWhitelistPath(path.to_owned()));
        self.put(TcmOperateCmd::FileWhitelistAdd, nlas).await.map(|_| ())
    }

    pub async fn delete_file_whitelist(&mut self, path: &str) -> Result<()> {
        let mut nlas = Vec::with_capacity(2);
        nlas.push(TcmAttr::FileWhitelistPath(path.to_owned()));
        self.put(TcmOperateCmd::FileWhitelistRemove, nlas).await.map(|_| ())
    }
}
