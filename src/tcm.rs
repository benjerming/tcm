use std::convert::TryFrom;

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, Nla, NlaBuffer, NlasIterator, Parseable,
    ParseableParametrized, emit_u32, parse_u32,
};
use netlink_packet_generic::{GenlFamily, GenlHeader, GenlMessage};

pub const TCM_FAMILY_NAME: &str = "tcm";
pub const TCM_MCGRP_NAME: &str = "hook";
pub const TCM_FAMILY_VERSION: u8 = 1;

const TCM_CMD_FORK_EVENT: u8 = 1;
const TCM_CMD_FORK_RET_EVENT: u8 = 2;
const TCM_CMD_FILE_EVENT: u8 = 3;

const TCM_ATTR_PARENT_PID: u16 = 1;
const TCM_ATTR_CHILD_PID: u16 = 2;
const TCM_ATTR_PARENT_PATH: u16 = 3;
const TCM_ATTR_CHILD_PATH: u16 = 4;
const TCM_ATTR_FILE_PID: u16 = 5;
const TCM_ATTR_FILE_FD: u16 = 6;
const TCM_ATTR_FILE_PATH: u16 = 7;
const TCM_ATTR_FILE_OPERATION: u16 = 8;
const TCM_ATTR_FILE_BYTES: u16 = 9;

fn parse_u64(payload: &[u8]) -> Result<u64, DecodeError> {
    if payload.len() < 8 {
        return Err(DecodeError::from(format!(
            "buffer too short for u64 (len={})",
            payload.len()
        )));
    }

    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(&payload[..8]);
    Ok(u64::from_ne_bytes(buffer))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmForkEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
    pub parent_path: String,
    pub child_path: String,
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmForkEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        let cmd = value.payload.cmd;
        if cmd != TcmCmd::ForkEvent {
            return Err(DecodeError::from(format!(
                "unexpected command: {cmd:?}, expected TcmCmd::ForkEvent",
            )));
        }

        Ok(TcmForkEvent {
            parent_pid: value.payload.parent_pid()?,
            child_pid: value.payload.child_pid()?,
            parent_path: value.payload.parent_path()?,
            child_path: value.payload.child_path()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmForkRetEvent {
    pub parent_pid: u32,
    pub child_pid: u32,
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmForkRetEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        let cmd = value.payload.cmd;
        if cmd != TcmCmd::ForkRetEvent {
            return Err(DecodeError::from(format!(
                "unexpected command: {cmd:?}, expected TcmCmd::ForkRetEvent",
            )));
        }

        Ok(TcmForkRetEvent {
            parent_pid: value.payload.parent_pid()?,
            child_pid: value.payload.child_pid()?,
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
                "unknown TCM file operation: {other}",
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmFileEvent {
    pub pid: u32,
    pub fd: u32,
    pub operation: TcmFileOp,
    pub bytes: u64,
    pub path: String,
}

impl TryFrom<GenlMessage<TcmMessage>> for TcmFileEvent {
    type Error = DecodeError;

    fn try_from(value: GenlMessage<TcmMessage>) -> Result<Self, Self::Error> {
        let cmd = value.payload.cmd;
        if cmd != TcmCmd::FileEvent {
            return Err(DecodeError::from(format!(
                "unexpected command: {cmd:?}, expected TcmCmd::FileEvent",
            )));
        }

        let pid = value.payload.file_pid()?;
        let fd = value.payload.file_fd()?;
        let path = value.payload.file_path()?;
        let operation = TcmFileOp::try_from(value.payload.file_operation()?)?;
        let bytes = value.payload.file_bytes()?;

        Ok(TcmFileEvent {
            pid,
            fd,
            operation,
            bytes,
            path,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmCmd {
    ForkEvent,
    ForkRetEvent,
    FileEvent,
}

impl From<TcmCmd> for u8 {
    fn from(cmd: TcmCmd) -> u8 {
        match cmd {
            TcmCmd::ForkEvent => TCM_CMD_FORK_EVENT,
            TcmCmd::ForkRetEvent => TCM_CMD_FORK_RET_EVENT,
            TcmCmd::FileEvent => TCM_CMD_FILE_EVENT,
        }
    }
}

impl TryFrom<u8> for TcmCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TCM_CMD_FORK_EVENT => Ok(TcmCmd::ForkEvent),
            TCM_CMD_FORK_RET_EVENT => Ok(TcmCmd::ForkRetEvent),
            TCM_CMD_FILE_EVENT => Ok(TcmCmd::FileEvent),
            other => Err(DecodeError::from(format!("unknown TCM command: {other}",))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmAttr {
    ParentPid(u32),
    ChildPid(u32),
    ParentPath(String),
    ChildPath(String),
    FilePid(u32),
    FileFd(u32),
    FilePath(String),
    FileOperation(u8),
    FileBytes(u64),
}

impl Nla for TcmAttr {
    fn value_len(&self) -> usize {
        match self {
            TcmAttr::ParentPid(_)
            | TcmAttr::ChildPid(_)
            | TcmAttr::FilePid(_)
            | TcmAttr::FileFd(_) => 4,
            TcmAttr::FileOperation(_) => 1,
            TcmAttr::FileBytes(_) => 8,
            TcmAttr::ParentPath(value) | TcmAttr::ChildPath(value) | TcmAttr::FilePath(value) => {
                value.len() + 1
            }
        }
    }

    fn kind(&self) -> u16 {
        match self {
            TcmAttr::ParentPid(_) => TCM_ATTR_PARENT_PID,
            TcmAttr::ChildPid(_) => TCM_ATTR_CHILD_PID,
            TcmAttr::ParentPath(_) => TCM_ATTR_PARENT_PATH,
            TcmAttr::ChildPath(_) => TCM_ATTR_CHILD_PATH,
            TcmAttr::FilePid(_) => TCM_ATTR_FILE_PID,
            TcmAttr::FileFd(_) => TCM_ATTR_FILE_FD,
            TcmAttr::FilePath(_) => TCM_ATTR_FILE_PATH,
            TcmAttr::FileOperation(_) => TCM_ATTR_FILE_OPERATION,
            TcmAttr::FileBytes(_) => TCM_ATTR_FILE_BYTES,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            TcmAttr::ParentPid(v) | TcmAttr::ChildPid(v) => {
                emit_u32(buffer, *v).expect("buffer too small for u32")
            }
            TcmAttr::ParentPath(value) | TcmAttr::ChildPath(value) => {
                let bytes = value.as_bytes();
                let len = bytes.len().min(buffer.len().saturating_sub(1));
                buffer.fill(0);
                buffer[..len].copy_from_slice(&bytes[..len]);
            }
            TcmAttr::FilePid(v) | TcmAttr::FileFd(v) => {
                emit_u32(buffer, *v).expect("buffer too small for u32")
            }
            TcmAttr::FilePath(value) => {
                let bytes = value.as_bytes();
                let len = bytes.len().min(buffer.len().saturating_sub(1));
                buffer.fill(0);
                buffer[..len].copy_from_slice(&bytes[..len]);
            }
            TcmAttr::FileOperation(v) => {
                buffer.fill(0);
                if !buffer.is_empty() {
                    buffer[0] = *v;
                }
            }
            TcmAttr::FileBytes(v) => {
                buffer.fill(0);
                if buffer.len() >= 8 {
                    buffer[..8].copy_from_slice(&v.to_ne_bytes());
                } else {
                    panic!("buffer too small for u64");
                }
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TcmAttr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        match buf.kind() {
            TCM_ATTR_PARENT_PID => Ok(TcmAttr::ParentPid(
                parse_u32(payload).context("failed to parse TCM_ATTR_PARENT_PID")?,
            )),
            TCM_ATTR_CHILD_PID => Ok(TcmAttr::ChildPid(
                parse_u32(payload).context("failed to parse TCM_ATTR_CHILD_PID")?,
            )),
            TCM_ATTR_PARENT_PATH => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::ParentPath(value))
            }
            TCM_ATTR_CHILD_PATH => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::ChildPath(value))
            }
            TCM_ATTR_FILE_PID => Ok(TcmAttr::FilePid(
                parse_u32(payload).context("failed to parse TCM_ATTR_FILE_PID")?,
            )),
            TCM_ATTR_FILE_FD => Ok(TcmAttr::FileFd(
                parse_u32(payload).context("failed to parse TCM_ATTR_FILE_FD")?,
            )),
            TCM_ATTR_FILE_PATH => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::FilePath(value))
            }
            TCM_ATTR_FILE_OPERATION => {
                let value = payload.first().copied().unwrap_or(0);
                Ok(TcmAttr::FileOperation(value))
            }
            TCM_ATTR_FILE_BYTES => Ok(TcmAttr::FileBytes(
                parse_u64(payload).context("failed to parse TCM_ATTR_FILE_BYTES")?,
            )),
            kind => Err(DecodeError::from(format!("unknown TCM attribute: {kind}",))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmMessage {
    pub cmd: TcmCmd,
    pub nlas: Vec<TcmAttr>,
}

impl TcmMessage {
    pub fn parent_pid(&self) -> Result<u32, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::ParentPid(pid) => Some(*pid),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_PARENT_PID")))
    }

    pub fn child_pid(&self) -> Result<u32, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::ChildPid(pid) => Some(*pid),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_CHILD_PID")))
    }

    pub fn parent_path(&self) -> Result<String, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::ParentPath(path) => Some(path.clone()),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_PARENT_PATH")))
    }

    pub fn child_path(&self) -> Result<String, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::ChildPath(path) => Some(path.clone()),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_CHILD_PATH")))
    }

    pub fn file_pid(&self) -> Result<u32, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::FilePid(pid) => Some(*pid),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_FILE_PID")))
    }

    pub fn file_fd(&self) -> Result<u32, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::FileFd(fd) => Some(*fd),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_FILE_FD")))
    }

    pub fn file_path(&self) -> Result<String, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::FilePath(path) => Some(path.clone()),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_FILE_PATH")))
    }

    pub fn file_operation(&self) -> Result<u8, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::FileOperation(op) => Some(*op),
                _ => None,
            })
            .ok_or(DecodeError::from(format!(
                "missing TCM_ATTR_FILE_OPERATION"
            )))
    }

    pub fn file_bytes(&self) -> Result<u64, DecodeError> {
        self.nlas
            .iter()
            .find_map(|attr| match attr {
                TcmAttr::FileBytes(bytes) => Some(*bytes),
                _ => None,
            })
            .ok_or(DecodeError::from(format!("missing TCM_ATTR_FILE_BYTES")))
    }

    // pub fn fork_event(&self) -> Option<TcmForkEvent> {
    //     if !matches!(self.cmd, TcmCmd::ForkEvent) {
    //         return None;
    //     }

    //     let parent_pid = self.parent_pid()?;
    //     let child_pid = self.child_pid()?;

    //     Some(TcmForkEvent {
    //         parent_pid,
    //         child_pid,
    //         parent_path: self.parent_path(),
    //         child_path: self.child_path(),
    //     })
    // }

    // pub fn fork_ret_event(&self) -> Option<TcmForkRetEvent> {
    //     if !matches!(self.cmd, TcmCmd::ForkRetEvent) {
    //         return None;
    //     }

    //     let parent_pid = self.parent_pid()?;
    //     let child_pid = self.child_pid()?;

    //     Some(TcmForkRetEvent {
    //         parent_pid,
    //         child_pid,
    //     })
    // }
}

impl GenlFamily for TcmMessage {
    fn family_name() -> &'static str {
        TCM_FAMILY_NAME
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        TCM_FAMILY_VERSION
    }
}

impl Emitable for TcmMessage {
    fn buffer_len(&self) -> usize {
        self.nlas.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.nlas.as_slice().emit(buffer)
    }
}

impl ParseableParametrized<[u8], GenlHeader> for TcmMessage {
    fn parse_with_param(payload: &[u8], header: GenlHeader) -> Result<Self, DecodeError> {
        let cmd = TcmCmd::try_from(header.cmd)?;
        let nlas = NlasIterator::new(payload)
            .map(|nla| nla.and_then(|nla| TcmAttr::parse(&nla)))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { cmd, nlas })
    }
}
