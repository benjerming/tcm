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

pub(crate) const FILE_LISTENER_PID_STAT_SIZE: usize = mem::size_of::<i32>() + mem::size_of::<u32>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileListenerPidStat {
    pub pid: i32,
    pub file_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmFileMonitorStats {
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

    pub fn proc_event_type(&self) -> Result<u8, DecodeError> {
        self.find_u8(|attr| match attr {
            TcmAttr::ProcEventType(event_type) => Some(*event_type),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PROC_EVENT_TYPE"))
    }

    pub fn ppid(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::Ppid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PPID"))
    }

    pub fn pid(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::Pid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PID"))
    }

    pub fn file_event_type(&self) -> Result<u8, DecodeError> {
        self.find_u8(|attr| match attr {
            TcmAttr::FileEventType(t) => Some(*t),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_EVENT_TYPE"))
    }

    pub fn fd(&self) -> Result<i32, DecodeError> {
        self.find_i32(|attr| match attr {
            TcmAttr::Fd(fd) => Some(*fd),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FD"))
    }

    #[allow(dead_code)]
    pub fn key(&self) -> Result<String, DecodeError> {
        self.find_string(|attr| match attr {
            TcmAttr::Key(key) => Some(key.clone()),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_KEY"))
    }

    pub fn path1(&self) -> Result<String, DecodeError> {
        self.find_string(|attr| match attr {
            TcmAttr::Path1(path) => Some(path.clone()),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PATH1"))
    }

    #[allow(dead_code)]
    pub fn path2(&self) -> Result<String, DecodeError> {
        self.find_string(|attr| match attr {
            TcmAttr::Path2(path) => Some(path.clone()),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PATH2"))
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

impl TryFrom<GenlMessage<TcmPayload>> for TcmFileMonitorStats {
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

        Ok(TcmFileMonitorStats {
            pid_table_size,
            pid_entry_count,
            file_entry_count,
            top_pid_count,
            top_pids,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmProcEventType {
    Fork,
    Exec,
    Exit,
}

impl TryFrom<u8> for TcmProcEventType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TcmProcEventType::Fork),
            2 => Ok(TcmProcEventType::Exec),
            3 => Ok(TcmProcEventType::Exit),
            other => Err(DecodeError::from(format!(
                "unknown TCM proc event type: {other} while parsing TcmProcEventType"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmProcEvent {
    pub event_type: TcmProcEventType,
    pub ppid: i32,
    pub pid: i32,
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmProcEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
        value.payload.expect_event(TcmEventCmd::ProcEvent)?;

        Ok(TcmProcEvent {
            event_type: TcmProcEventType::try_from(value.payload.proc_event_type()?)?,
            ppid: value.payload.ppid()?,
            pid: value.payload.pid()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmFileEventType {
    Open,
    Write,
    Close,
}

impl TryFrom<u8> for TcmFileEventType {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TcmFileEventType::Open),
            2 => Ok(TcmFileEventType::Write),
            3 => Ok(TcmFileEventType::Close),
            other => Err(DecodeError::from(format!(
                "unknown TCM file event type: {other} while parsing TcmFileEventType"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmFileEvent {
    pub event_type: TcmFileEventType,
    pub fd: i32,
    pub pid: i32,
    pub path1: String,
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmFileEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
        value.payload.expect_event(TcmEventCmd::FileEvent)?;

        let pid = value.payload.pid()?;
        let fd = value.payload.fd()?;
        let path1 = value.payload.path1()?;
        // let path2 = value.payload.path2()?;
        let event_type = TcmFileEventType::try_from(value.payload.file_event_type()?)?;

        Ok(TcmFileEvent {
            event_type,
            fd,
            pid,
            path1,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmEvent {
    File(TcmFileEvent),
    Proc(TcmProcEvent),
    FileStats(TcmFileMonitorStats),
}

impl TryFrom<GenlMessage<TcmPayload>> for TcmEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmPayload>) -> Result<Self, Self::Error> {
        match value.payload.event_command() {
            Ok(TcmEventCmd::ProcEvent) => TcmProcEvent::try_from(value).map(TcmEvent::Proc),
            Ok(TcmEventCmd::FileEvent) => TcmFileEvent::try_from(value).map(TcmEvent::File),
            Ok(TcmEventCmd::FileStatsEvent) => {
                TcmFileMonitorStats::try_from(value).map(TcmEvent::FileStats)
            }
            Err(err) => Err(err),
        }
    }
}

pub trait TcmEventHandler: Send + Sync {
    fn on_file(&self, _event: TcmFileEvent) {}
    fn on_proc(&self, _event: TcmProcEvent) {}
    fn on_file_stats(&self, _event: TcmFileMonitorStats) {}
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
        TcmEvent::Proc(event) => handler.on_proc(event),
        TcmEvent::File(event) => handler.on_file(event),
        TcmEvent::FileStats(event) => handler.on_file_stats(event),
    }
}
