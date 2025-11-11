use std::convert::TryFrom;
use std::mem;

use genetlink::message::{RawGenlMessage, map_from_rawgenlmsg};
use log::warn;
use netlink_packet_core::{DecodeError, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;

use super::command::TcmEventCmd;
use super::message::TcmMessage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmForkRetEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmForkRetEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        value.payload.expect_event(TcmEventCmd::ForkRetEvent)?;

        Ok(TcmForkRetEvent {
            parent_pid: value.payload.parent_pid()?,
            child_pid: value.payload.child_pid()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmExitEvent {
    pub pid: u32,
    pub code: i32,
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmExitEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        value.payload.expect_event(TcmEventCmd::ExitEvent)?;

        Ok(TcmExitEvent {
            pid: value.payload.exit_pid()?,
            code: value.payload.exit_code()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmFileOp {
    Open,
    Write,
    Close,
}

impl TryFrom<u8> for TcmFileOp {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TcmFileOp::Open),
            2 => Ok(TcmFileOp::Write),
            3 => Ok(TcmFileOp::Close),
            other => Err(DecodeError::from(format!(
                "unknown TCM file operation: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmFileEvent {
    pub pid: u32,
    pub fd: u32,
    pub operation: TcmFileOp,
    pub path: String,
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmFileEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        value.payload.expect_event(TcmEventCmd::FileEvent)?;

        let pid = value.payload.file_pid()?;
        let fd = value.payload.file_fd()?;
        let path = value.payload.file_path()?;
        let operation = TcmFileOp::try_from(value.payload.file_operation()?)?;

        Ok(TcmFileEvent {
            pid,
            fd,
            operation,
            path,
        })
    }
}

pub(crate) const FILE_LISTENER_PID_STAT_SIZE: usize = mem::size_of::<i32>() + mem::size_of::<u32>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileListenerPidStat {
    pub pid: i32,
    pub file_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmFileStats {
    pub pid_table_size: u32,
    pub pid_entry_count: u32,
    pub file_entry_count: u32,
    pub top_pid_count: u32,
    pub top_pids: Vec<FileListenerPidStat>,
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmFileStats {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        value.payload.expect_event(TcmEventCmd::FileStatsEvent)?;

        let pid_table_size = value.payload.file_stats_pid_table_size()?;
        let pid_entry_count = value.payload.file_stats_pid_entry_count()?;
        let file_entry_count = value.payload.file_stats_file_entry_count()?;
        let top_pid_count = value.payload.file_stats_top_pid_count()?;
        let top_pids = value.payload.file_stats_top_pids()?;

        if top_pids.len() != top_pid_count as usize {
            return Err(DecodeError::from(format!(
                "top pid count mismatch: declared {}, parsed {} entries",
                top_pid_count,
                top_pids.len()
            )));
        }

        Ok(TcmFileStats {
            pid_table_size,
            pid_entry_count,
            file_entry_count,
            top_pid_count,
            top_pids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmEvent {
    ForkRet(TcmForkRetEvent),
    File(TcmFileEvent),
    Exit(TcmExitEvent),
    FileStats(TcmFileStats),
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        match value.payload.event_command() {
            Ok(TcmEventCmd::ForkRetEvent) => {
                TcmForkRetEvent::try_from(value).map(TcmEvent::ForkRet)
            }
            Ok(TcmEventCmd::FileEvent) => TcmFileEvent::try_from(value).map(TcmEvent::File),
            Ok(TcmEventCmd::ExitEvent) => TcmExitEvent::try_from(value).map(TcmEvent::Exit),
            Ok(TcmEventCmd::FileStatsEvent) => {
                TcmFileStats::try_from(value).map(TcmEvent::FileStats)
            }
            Err(err) => Err(err),
        }
    }
}

pub trait TcmEventHandler: Send + Sync {
    fn on_fork_ret(&self, _event: TcmForkRetEvent) {}
    fn on_file(&self, _event: TcmFileEvent) {}
    fn on_exit(&self, _event: TcmExitEvent) {}
    fn on_file_stats(&self, _event: TcmFileStats) {}
}

pub fn handle_raw_message(message: NetlinkMessage<RawGenlMessage>, handler: &dyn TcmEventHandler) {
    match map_from_rawgenlmsg::<TcmMessage>(message) {
        Ok(decoded) => handle_netlink_message(decoded, handler),
        Err(err) => {
            warn!("failed to decode message: {err:?}");
        }
    }
}

fn handle_netlink_message(
    message: NetlinkMessage<GenlMessage<TcmMessage>>,
    handler: &dyn TcmEventHandler,
) {
    match message.payload {
        NetlinkPayload::InnerMessage(genlmsg) => match TcmEvent::try_from(genlmsg) {
            Ok(event) => dispatch_event(handler, event),
            Err(err) => {
                warn!("failed to decode event message: {err:?}");
            }
        },
        NetlinkPayload::Error(err) => {
            warn!("received netlink error: {err:?}");
        }
        other => {
            warn!("ignoring non data payload: {other:?}");
        }
    }
}

fn dispatch_event(handler: &dyn TcmEventHandler, event: TcmEvent) {
    match event {
        TcmEvent::ForkRet(event) => handler.on_fork_ret(event),
        TcmEvent::File(event) => handler.on_file(event),
        TcmEvent::Exit(event) => handler.on_exit(event),
        TcmEvent::FileStats(event) => handler.on_file_stats(event),
    }
}
