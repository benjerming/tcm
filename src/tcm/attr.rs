use netlink_packet_core::{
    DecodeError, ErrorContext, Nla, NlaBuffer, Parseable, emit_u32, parse_u32,
};

use super::constants::{
    TCM_GENL_ATTR_FD, TCM_GENL_ATTR_FILE_EVENT_TYPE, TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT,
    TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT, TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE,
    TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT, TCM_GENL_ATTR_FILE_STATS_TOP_PIDS, TCM_GENL_ATTR_KEY,
    TCM_GENL_ATTR_KEY_MAX_LEN, TCM_GENL_ATTR_PATH1, TCM_GENL_ATTR_PATH2, TCM_GENL_ATTR_PID,
    TCM_GENL_ATTR_PPID, TCM_GENL_ATTR_PROC_EVENT_TYPE,
};
use super::message::{FILE_LISTENER_PID_STAT_SIZE, FileListenerPidStat};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmAttr {
    Key(String),
    Fd(i32),
    Pid(i32),
    Ppid(i32),
    ProcEventType(u8),
    FileEventType(u8),
    Path1(String),
    #[allow(dead_code)]
    Path2(String),
    FileStatsPidTableSize(u32),
    FileStatsPidEntryCount(u32),
    FileStatsFileEntryCount(u32),
    FileStatsTopPidCount(u32),
    FileStatsTopPids(Vec<FileListenerPidStat>),
    FileWhitelistPath(String),
}

impl TcmAttr {
    fn parse_u8(payload: &[u8]) -> Result<u8, DecodeError> {
        if payload.len() < 1 {
            return Err(DecodeError::from(format!(
                "buffer too short for u8 (len={})",
                payload.len()
            )));
        }
        Ok(payload[0])
    }

    fn parse_i32(payload: &[u8]) -> Result<i32, DecodeError> {
        if payload.len() < 4 {
            return Err(DecodeError::from(format!(
                "buffer too short for i32 (len={})",
                payload.len()
            )));
        }

        let mut buffer = [0u8; 4];
        buffer.copy_from_slice(&payload[..4]);
        Ok(i32::from_ne_bytes(buffer))
    }

    fn emit_u8(buffer: &mut [u8], value: u8) {
        buffer.fill(0);
        if buffer.len() < 1 {
            panic!("buffer too small for u8");
        }
        buffer[0] = value;
    }

    fn emit_i32(buffer: &mut [u8], value: i32) {
        buffer.fill(0);
        if buffer.len() < 4 {
            panic!("buffer too small for i32");
        }
        buffer[..4].copy_from_slice(&value.to_ne_bytes());
    }
}

impl Nla for TcmAttr {
    fn value_len(&self) -> usize {
        match self {
            TcmAttr::Fd(_)
            | TcmAttr::Pid(_)
            | TcmAttr::Ppid(_)
            | TcmAttr::FileStatsPidTableSize(_)
            | TcmAttr::FileStatsPidEntryCount(_)
            | TcmAttr::FileStatsFileEntryCount(_)
            | TcmAttr::FileStatsTopPidCount(_) => 4,
            TcmAttr::ProcEventType(_) | TcmAttr::FileEventType(_) => 1,
            TcmAttr::Key(_) => TCM_GENL_ATTR_KEY_MAX_LEN,
            TcmAttr::Path1(value) => value.len() + 1,
            TcmAttr::Path2(value) => value.len() + 1,
            TcmAttr::FileStatsTopPids(values) => values.len() * FILE_LISTENER_PID_STAT_SIZE,
            TcmAttr::FileWhitelistPath(value) => value.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            TcmAttr::Fd(_) => TCM_GENL_ATTR_FD,
            TcmAttr::Key(_) => TCM_GENL_ATTR_KEY,
            TcmAttr::Pid(_) => TCM_GENL_ATTR_PID,
            TcmAttr::Ppid(_) => TCM_GENL_ATTR_PPID,
            TcmAttr::ProcEventType(_) => TCM_GENL_ATTR_PROC_EVENT_TYPE,
            TcmAttr::FileEventType(_) => TCM_GENL_ATTR_FILE_EVENT_TYPE,
            TcmAttr::Path1(_) => TCM_GENL_ATTR_PATH1,
            TcmAttr::Path2(_) => TCM_GENL_ATTR_PATH2,
            TcmAttr::FileStatsPidTableSize(_) => TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE,
            TcmAttr::FileStatsPidEntryCount(_) => TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT,
            TcmAttr::FileStatsFileEntryCount(_) => TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT,
            TcmAttr::FileStatsTopPidCount(_) => TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT,
            TcmAttr::FileStatsTopPids(_) => TCM_GENL_ATTR_FILE_STATS_TOP_PIDS,
            TcmAttr::FileWhitelistPath(_) => TCM_GENL_ATTR_PATH1,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            TcmAttr::Fd(v) => Self::emit_i32(buffer, *v),
            TcmAttr::Key(value) => {
                let bytes = value.as_bytes();
                let len = bytes.len().min(buffer.len().saturating_sub(1));
                buffer.fill(0);
                buffer[..len].copy_from_slice(&bytes[..len]);
            }
            TcmAttr::Pid(v) | TcmAttr::Ppid(v) => Self::emit_i32(buffer, *v),
            TcmAttr::FileEventType(v) | TcmAttr::ProcEventType(v) => Self::emit_u8(buffer, *v),
            TcmAttr::Path1(value) | TcmAttr::Path2(value) => {
                let bytes = value.as_bytes();
                let len = bytes.len().min(buffer.len().saturating_sub(1));
                buffer.fill(0);
                buffer[..len].copy_from_slice(&bytes[..len]);
            }
            TcmAttr::FileStatsPidTableSize(v)
            | TcmAttr::FileStatsPidEntryCount(v)
            | TcmAttr::FileStatsFileEntryCount(v)
            | TcmAttr::FileStatsTopPidCount(v) => {
                emit_u32(buffer, *v).expect("buffer too small for u32")
            }
            TcmAttr::FileStatsTopPids(values) => {
                let required = values.len() * FILE_LISTENER_PID_STAT_SIZE;
                assert!(
                    buffer.len() >= required,
                    "buffer too small for top pid stats"
                );
                for (idx, stat) in values.iter().enumerate() {
                    let offset = idx * FILE_LISTENER_PID_STAT_SIZE;
                    buffer[offset..offset + 4].copy_from_slice(&stat.pid.to_ne_bytes());
                    buffer[offset + 4..offset + 8].copy_from_slice(&stat.file_count.to_ne_bytes());
                }
            }
            TcmAttr::FileWhitelistPath(value) => {
                let bytes = value.as_bytes();
                let len = bytes.len().min(buffer.len().saturating_sub(1));
                buffer.fill(0);
                buffer[..len].copy_from_slice(&bytes[..len]);
            }
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for TcmAttr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        match buf.kind() {
            TCM_GENL_ATTR_FD => Ok(TcmAttr::Fd(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_FD")?,
            )),
            TCM_GENL_ATTR_PID => Ok(TcmAttr::Pid(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_PID")?,
            )),
            TCM_GENL_ATTR_PPID => Ok(TcmAttr::Ppid(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_PPID")?,
            )),
            TCM_GENL_ATTR_PROC_EVENT_TYPE => Ok(TcmAttr::ProcEventType(
                Self::parse_u8(payload).context("failed to parse TCM_ATTR_PROC_EVENT_TYPE")?,
            )),
            TCM_GENL_ATTR_FILE_EVENT_TYPE => Ok(TcmAttr::FileEventType(
                Self::parse_u8(payload).context("failed to parse TCM_ATTR_FILE_EVENT_TYPE")?,
            )),
            TCM_GENL_ATTR_KEY | TCM_GENL_ATTR_PATH1 | TCM_GENL_ATTR_PATH2 => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::Path1(value))
            }
            TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE => Ok(TcmAttr::FileStatsPidTableSize(
                parse_u32(payload).context("failed to parse TCM_ATTR_FILE_STATS_PID_TABLE_SIZE")?,
            )),
            TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT => Ok(TcmAttr::FileStatsPidEntryCount(
                parse_u32(payload)
                    .context("failed to parse TCM_ATTR_FILE_STATS_PID_ENTRY_COUNT")?,
            )),
            TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT => Ok(TcmAttr::FileStatsFileEntryCount(
                parse_u32(payload)
                    .context("failed to parse TCM_ATTR_FILE_STATS_FILE_ENTRY_COUNT")?,
            )),
            TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT => Ok(TcmAttr::FileStatsTopPidCount(
                parse_u32(payload).context("failed to parse TCM_ATTR_FILE_STATS_TOP_PID_COUNT")?,
            )),
            TCM_GENL_ATTR_FILE_STATS_TOP_PIDS => {
                if payload.len() % FILE_LISTENER_PID_STAT_SIZE != 0 {
                    return Err(DecodeError::from(format!(
                        "invalid payload length for TCM_ATTR_FILE_STATS_TOP_PIDS: {}",
                        payload.len()
                    )));
                }

                let mut stats = Vec::with_capacity(payload.len() / FILE_LISTENER_PID_STAT_SIZE);
                for chunk in payload.chunks_exact(FILE_LISTENER_PID_STAT_SIZE) {
                    let mut pid_bytes = [0u8; 4];
                    pid_bytes.copy_from_slice(&chunk[..4]);
                    let pid = i32::from_ne_bytes(pid_bytes);

                    let mut count_bytes = [0u8; 4];
                    count_bytes.copy_from_slice(&chunk[4..8]);
                    let file_count = u32::from_ne_bytes(count_bytes);

                    stats.push(FileListenerPidStat { pid, file_count });
                }

                Ok(TcmAttr::FileStatsTopPids(stats))
            }
            kind => Err(DecodeError::from(format!("unknown TCM attr: {kind}"))),
        }
    }
}
