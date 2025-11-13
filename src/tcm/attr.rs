use netlink_packet_core::{
    DecodeError, ErrorContext, Nla, NlaBuffer, Parseable, emit_u32, parse_u32,
};

use super::constants::{
    TCM_GENL_ATTR_CHILD_PATH, TCM_GENL_ATTR_CHILD_PID, TCM_GENL_ATTR_EXIT_CODE,
    TCM_GENL_ATTR_EXIT_PID, TCM_GENL_ATTR_FILE_FD, TCM_GENL_ATTR_FILE_OPERATION,
    TCM_GENL_ATTR_FILE_PATH, TCM_GENL_ATTR_FILE_PID, TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT,
    TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT, TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE,
    TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT, TCM_GENL_ATTR_FILE_STATS_TOP_PIDS,
    TCM_GENL_ATTR_FILE_WHITELIST_PATH, TCM_GENL_ATTR_PARENT_PATH, TCM_GENL_ATTR_PARENT_PID,
};
use super::message::{FILE_LISTENER_PID_STAT_SIZE, FileListenerPidStat};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmAttr {
    ParentPid(i32),
    ChildPid(i32),
    ParentPath(String),
    ChildPath(String),
    FilePid(i32),
    FileFd(i32),
    FilePath(String),
    FileOperation(u8),
    ExitPid(i32),
    ExitCode(i32),
    FileStatsPidTableSize(u32),
    FileStatsPidEntryCount(u32),
    FileStatsFileEntryCount(u32),
    FileStatsTopPidCount(u32),
    FileStatsTopPids(Vec<FileListenerPidStat>),
    FileWhitelistPath(String),
}

impl TcmAttr {
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
            TcmAttr::ParentPid(_)
            | TcmAttr::ChildPid(_)
            | TcmAttr::FilePid(_)
            | TcmAttr::FileFd(_)
            | TcmAttr::ExitPid(_)
            | TcmAttr::ExitCode(_)
            | TcmAttr::FileStatsPidTableSize(_)
            | TcmAttr::FileStatsPidEntryCount(_)
            | TcmAttr::FileStatsFileEntryCount(_)
            | TcmAttr::FileStatsTopPidCount(_) => 4,
            TcmAttr::FileOperation(_) => 1,
            TcmAttr::ParentPath(value) | TcmAttr::ChildPath(value) | TcmAttr::FilePath(value) => {
                value.len() + 1
            }
            TcmAttr::FileStatsTopPids(values) => values.len() * FILE_LISTENER_PID_STAT_SIZE,
            TcmAttr::FileWhitelistPath(value) => value.len() + 1,
        }
    }

    fn kind(&self) -> u16 {
        match self {
            TcmAttr::ParentPid(_) => TCM_GENL_ATTR_PARENT_PID,
            TcmAttr::ChildPid(_) => TCM_GENL_ATTR_CHILD_PID,
            TcmAttr::ParentPath(_) => TCM_GENL_ATTR_PARENT_PATH,
            TcmAttr::ChildPath(_) => TCM_GENL_ATTR_CHILD_PATH,
            TcmAttr::FilePid(_) => TCM_GENL_ATTR_FILE_PID,
            TcmAttr::FileFd(_) => TCM_GENL_ATTR_FILE_FD,
            TcmAttr::FilePath(_) => TCM_GENL_ATTR_FILE_PATH,
            TcmAttr::FileOperation(_) => TCM_GENL_ATTR_FILE_OPERATION,
            TcmAttr::ExitPid(_) => TCM_GENL_ATTR_EXIT_PID,
            TcmAttr::ExitCode(_) => TCM_GENL_ATTR_EXIT_CODE,
            TcmAttr::FileStatsPidTableSize(_) => TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE,
            TcmAttr::FileStatsPidEntryCount(_) => TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT,
            TcmAttr::FileStatsFileEntryCount(_) => TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT,
            TcmAttr::FileStatsTopPidCount(_) => TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT,
            TcmAttr::FileStatsTopPids(_) => TCM_GENL_ATTR_FILE_STATS_TOP_PIDS,
            TcmAttr::FileWhitelistPath(_) => TCM_GENL_ATTR_FILE_WHITELIST_PATH,
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            TcmAttr::ParentPid(v) | TcmAttr::ChildPid(v) => Self::emit_i32(buffer, *v),
            TcmAttr::ParentPath(value) | TcmAttr::ChildPath(value) => {
                let bytes = value.as_bytes();
                let len = bytes.len().min(buffer.len().saturating_sub(1));
                buffer.fill(0);
                buffer[..len].copy_from_slice(&bytes[..len]);
            }
            TcmAttr::FilePid(v) | TcmAttr::FileFd(v) => Self::emit_i32(buffer, *v),
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
            TcmAttr::ExitPid(v) => Self::emit_i32(buffer, *v),
            TcmAttr::ExitCode(v) => Self::emit_i32(buffer, *v),
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
            TCM_GENL_ATTR_PARENT_PID => Ok(TcmAttr::ParentPid(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_PARENT_PID")?,
            )),
            TCM_GENL_ATTR_CHILD_PID => Ok(TcmAttr::ChildPid(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_CHILD_PID")?,
            )),
            TCM_GENL_ATTR_PARENT_PATH => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::ParentPath(value))
            }
            TCM_GENL_ATTR_CHILD_PATH => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::ChildPath(value))
            }
            TCM_GENL_ATTR_FILE_PID => Ok(TcmAttr::FilePid(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_FILE_PID")?,
            )),
            TCM_GENL_ATTR_FILE_FD => Ok(TcmAttr::FileFd(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_FILE_FD")?,
            )),
            TCM_GENL_ATTR_FILE_PATH => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::FilePath(value))
            }
            TCM_GENL_ATTR_FILE_OPERATION => {
                let value = payload.first().copied().unwrap_or(0);
                Ok(TcmAttr::FileOperation(value))
            }
            TCM_GENL_ATTR_EXIT_PID => Ok(TcmAttr::ExitPid(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_EXIT_PID")?,
            )),
            TCM_GENL_ATTR_EXIT_CODE => Ok(TcmAttr::ExitCode(
                Self::parse_i32(payload).context("failed to parse TCM_ATTR_EXIT_CODE")?,
            )),
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
            TCM_GENL_ATTR_FILE_WHITELIST_PATH => {
                let len = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                let value = String::from_utf8_lossy(&payload[..len]).into_owned();
                Ok(TcmAttr::FileWhitelistPath(value))
            }
            kind => Err(DecodeError::from(format!("unknown TCM attr: {kind}"))),
        }
    }
}
