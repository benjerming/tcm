use std::convert::TryFrom;
use std::mem;

use genetlink::message::{RawGenlMessage, map_from_rawgenlmsg};
use log::warn;
use netlink_packet_core::{
    DecodeError, Emitable, NetlinkMessage, NetlinkPayload, NlasIterator, Parseable,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader, GenlMessage};

use super::attr::TcmAttr;
use super::command::{TcmCommand, TcmEventCmd};
use super::constants::{genl_family_name, genl_family_version};

pub(crate) const FILE_LISTENER_PID_STAT_SIZE: usize =
    mem::size_of::<i32>() + mem::size_of::<u32>();

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmPayload {
    pub cmd: TcmCommand,
    pub nlas: Vec<TcmAttr>,
}

impl TcmPayload {
    pub fn event_command(&self) -> Result<TcmEventCmd, DecodeError> {
        match self.cmd {
            TcmCommand::Event(cmd) => Ok(cmd),
            TcmCommand::Operation(op) => Err(DecodeError::from(format!(
                "unexpected operation command: {op:?}"
            ))),
        }
    }

    pub fn expect_event(&self, expected: TcmEventCmd) -> Result<(), DecodeError> {
        let actual = self.event_command()?;
        if actual == expected {
            Ok(())
        } else {
            Err(DecodeError::from(format!(
                "unexpected event command: {actual:?}, expected {expected:?}"
            )))
        }
    }

    pub fn parent_pid(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::ParentPid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PARENT_PID"))
    }

    pub fn child_pid(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::ChildPid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_CHILD_PID"))
    }

    #[allow(dead_code)]
    pub fn parent_path(&self) -> Result<String, DecodeError> {
        self.find_string(|attr| match attr {
            TcmAttr::ParentPath(path) => Some(path.clone()),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PARENT_PATH"))
    }

    #[allow(dead_code)]
    pub fn child_path(&self) -> Result<String, DecodeError> {
        self.find_string(|attr| match attr {
            TcmAttr::ChildPath(path) => Some(path.clone()),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_CHILD_PATH"))
    }

    pub fn file_pid(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::FilePid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_PID"))
    }

    pub fn file_fd(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::FileFd(fd) => Some(*fd),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_FD"))
    }

    pub fn file_path(&self) -> Result<String, DecodeError> {
        self.find_string(|attr| match attr {
            TcmAttr::FilePath(path) => Some(path.clone()),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_PATH"))
    }

    pub fn file_operation(&self) -> Result<u8, DecodeError> {
        self.find_u8(|attr| match attr {
            TcmAttr::FileOperation(op) => Some(*op),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_OPERATION"))
    }

    pub fn exit_pid(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::ExitPid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_EXIT_PID"))
    }

    pub fn exit_code(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::ExitCode(code) => Some(*code),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_EXIT_CODE"))
    }

    pub fn file_stats_pid_table_size(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
            TcmAttr::FileStatsPidTableSize(size) => Some(*size),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_STATS_PID_TABLE_SIZE"))
    }

    pub fn file_stats_pid_entry_count(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
            TcmAttr::FileStatsPidEntryCount(count) => Some(*count),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_STATS_PID_ENTRY_COUNT"))
    }

    pub fn file_stats_file_entry_count(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
            TcmAttr::FileStatsFileEntryCount(count) => Some(*count),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_STATS_FILE_ENTRY_COUNT"))
    }

    pub fn file_stats_top_pid_count(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
            TcmAttr::FileStatsTopPidCount(count) => Some(*count),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_STATS_TOP_PID_COUNT"))
    }

    pub fn file_stats_top_pids(&self) -> Result<Vec<FileListenerPidStat>, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::FileStatsTopPids(stats) => Some(stats.clone()),
                _ => None,
            })
            .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_STATS_TOP_PIDS"))
    }

    fn find_u32<F>(&self, mut f: F) -> Option<u32>
    where
        F: FnMut(&TcmAttr) -> Option<u32>,
    {
        self.nlas.iter().find_map(|attr| f(attr))
    }

    fn find_i32<F>(&self, mut f: F) -> Option<i32>
    where
        F: FnMut(&TcmAttr) -> Option<i32>,
    {
        self.nlas.iter().find_map(|attr| f(attr))
    }

    fn find_u8<F>(&self, mut f: F) -> Option<u8>
    where
        F: FnMut(&TcmAttr) -> Option<u8>,
    {
        self.nlas.iter().find_map(|attr| f(attr))
    }

    fn find_string<F>(&self, mut f: F) -> Option<String>
    where
        F: FnMut(&TcmAttr) -> Option<String>,
    {
        self.nlas.iter().find_map(|attr| f(attr))
    }
}

impl GenlFamily for TcmPayload {
    fn family_name() -> &'static str {
        genl_family_name()
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        genl_family_version()
    }
}

impl Emitable for TcmPayload {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }
}

impl ParseableParametrized<[u8], GenlHeader> for TcmPayload {
    fn parse_with_param(payload: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        let cmd = TcmCommand::try_from(header.cmd)?;
        let nlas = NlasIterator::new(payload)
            .map(|nla| nla.and_then(|nla| TcmAttr::parse(&nla)))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { cmd, nlas })
    }
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmFileStats {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
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
pub struct TcmForkRetEvent {
    pub parent_pid: i32,
    pub child_pid: i32,
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmForkRetEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
        value.payload.expect_event(TcmEventCmd::ForkRetEvent)?;

        Ok(TcmForkRetEvent {
            parent_pid: value.payload.parent_pid()?,
            child_pid: value.payload.child_pid()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmExitEvent {
    pub pid: i32,
    pub code: i32,
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmExitEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
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
    pub pid: i32,
    pub fd: i32,
    pub operation: TcmFileOp,
    pub path: String,
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmFileEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmEvent {
    ForkRet(TcmForkRetEvent),
    File(TcmFileEvent),
    Exit(TcmExitEvent),
    FileStats(TcmFileStats),
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
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
    match map_from_rawgenlmsg::<TcmPayload>(message) {
        Ok(decoded) => handle_netlink_message(decoded, handler),
        Err(err) => {
            warn!("failed to decode message: {err:?}");
        }
    }
}

fn handle_netlink_message(
    message: NetlinkMessage<GenlMessage<TcmPayload>>,
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
