use std::sync::Arc;

use futures::{Stream, stream::StreamExt};
use genetlink::message::RawGenlMessage;
use netlink_packet_core::NetlinkMessage;
use tokio::{select, sync::watch, task::JoinHandle};

type MessageStream = Box<
    dyn Stream<
            Item = (
                NetlinkMessage<RawGenlMessage>,
                netlink_proto::sys::SocketAddr,
            ),
        > + Send
        + Unpin,
>;

type MessageCallback = Arc<dyn Fn(NetlinkMessage<RawGenlMessage>) + Send + Sync + 'static>;

/// 负责监听内核广播的异步任务，支持动态启用/禁用。
pub struct TcmGenlBroadcastListener {
    control_tx: watch::Sender<bool>,
    join_handle: JoinHandle<()>,
}

impl TcmGenlBroadcastListener {
    /// 启动监听任务，并返回控制句柄。
    pub fn spawn<S, F>(stream: S, on_message: F) -> Self
    where
        S: futures::Stream<
                Item = (
                    NetlinkMessage<RawGenlMessage>,
                    netlink_proto::sys::SocketAddr,
                ),
            > + Send
            + Unpin
            + 'static,
        F: Fn(NetlinkMessage<RawGenlMessage>) + Send + Sync + 'static,
    {
        let (control_tx, mut control_rx) = watch::channel(false);
        let callback: MessageCallback = Arc::new(on_message);
        let mut stream: MessageStream = Box::new(stream);
        let join_handle = tokio::spawn(async move {
            let mut enabled = *control_rx.borrow();
            loop {
                select! {
                    changed = control_rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        enabled = *control_rx.borrow();
                    }
                    maybe_message = stream.next() => {
                        match maybe_message {
                            Some((message, _addr)) => {
                                if enabled {
                                    (callback)(message);
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        });

        Self {
            control_tx,
            join_handle,
        }
    }

    /// 启用广播消息处理。
    pub fn enable(&self) {
        let _ = self.control_tx.send(true);
    }

    /// 禁用广播消息处理（仍会消费消息但不回调）。
    pub fn disable(&self) {
        let _ = self.control_tx.send(false);
    }

    /// 等待监听任务结束。
    pub async fn shutdown(self) {
        let Self {
            control_tx,
            join_handle,
        } = self;
        let _ = control_tx.send(false);
        drop(control_tx);
        let _ = join_handle.await;
    }
}
