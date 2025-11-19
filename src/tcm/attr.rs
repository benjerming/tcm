use netlink_packet_core::{
    DecodeError, ErrorContext, NLA_F_NESTED, Nla, NlaBuffer, NlasIterator, Parseable, emit_u32,
    parse_u32,
};

use super::constants::*;
use super::message::{FILE_LISTENER_PID_STAT_SIZE, FileListenerPidStat};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcmAttr {
    Key(String),
    Fd(i32),
    Pid(i32),
    Ppid(i32),
    PathList(Vec<String>),
    ProcList(Vec<i32>),
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
}

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub enum TcmProcListEntry {
//     Proc(i32),
//     ProcTree(i32),
// }

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub enum TcmPathListEntry {
//     Path(String),
// }

const NLA_HEADER_LEN: usize = 4;

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

    fn nla_attr_len(payload_len: usize) -> usize {
        NLA_HEADER_LEN + payload_len
    }

    fn nla_align(len: usize) -> usize {
        (len + 3) & !3
    }

    fn nested_entry_total_len(payload_len: usize) -> usize {
        Self::nla_align(Self::nla_attr_len(payload_len))
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
            TcmAttr::PathList(items) => items
                .iter()
                .map(|item| Self::nested_entry_total_len(item.len() + 1))
                .sum(),
            TcmAttr::ProcList(items) => items.iter().map(|_| Self::nested_entry_total_len(4)).sum(),
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
            TcmAttr::PathList(_) => TCM_GENL_ATTR_PATH_LIST | NLA_F_NESTED,
            TcmAttr::ProcList(_) => TCM_GENL_ATTR_PROC_LIST | NLA_F_NESTED,
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
            TcmAttr::PathList(values) => {
                let mut offset = 0;
                for value in values {
                    let payload_len = value.len() + 1;
                    let attr_len = Self::nla_attr_len(payload_len);
                    let aligned_len = Self::nla_align(attr_len);

                    let slice = &mut buffer[offset..offset + aligned_len];
                    slice.fill(0);

                    slice[..2].copy_from_slice(&(attr_len as u16).to_ne_bytes());
                    slice[2..4].copy_from_slice(&TCM_GENL_PATH_LIST_ATTR_FILE_ENTRY.to_ne_bytes());

                    let bytes = value.as_bytes();
                    let copy_len = bytes.len().min(payload_len.saturating_sub(1));
                    slice[4..4 + copy_len].copy_from_slice(&bytes[..copy_len]);

                    offset += aligned_len;
                }
            }
            TcmAttr::ProcList(values) => {
                let mut offset = 0;
                for value in values {
                    let payload_len = 4;
                    let attr_len = Self::nla_attr_len(payload_len);
                    let aligned_len = Self::nla_align(attr_len);

                    let slice = &mut buffer[offset..offset + aligned_len];
                    slice.fill(0);

                    slice[..2].copy_from_slice(&(attr_len as u16).to_ne_bytes());

                    let (attr_type, payload_value) = if *value >= 0 {
                        (TCM_GENL_PROC_LIST_ATTR_PROC_TREE_ENTRY, *value)
                    } else {
                        (TCM_GENL_PROC_LIST_ATTR_PROC_ENTRY, value.abs())
                    };
                    slice[2..4].copy_from_slice(&attr_type.to_ne_bytes());
                    Self::emit_i32(&mut slice[4..4 + payload_len], payload_value);

                    offset += aligned_len;
                }
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
            TCM_GENL_ATTR_PATH_LIST => {
                let mut paths = Vec::new();
                for nested in NlasIterator::new(payload) {
                    let nla =
                        nested.context("failed to parse nested attr in TCM_ATTR_PATH_LIST")?;
                    if nla.kind() != TCM_GENL_PATH_LIST_ATTR_FILE_ENTRY {
                        continue;
                    }
                    let value = nla.value();
                    let len = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                    let path = String::from_utf8_lossy(&value[..len]).into_owned();
                    paths.push(path);
                }

                Ok(TcmAttr::PathList(paths))
            }
            TCM_GENL_ATTR_PROC_LIST => {
                let mut procs = Vec::new();
                for nested in NlasIterator::new(payload) {
                    let nla =
                        nested.context("failed to parse nested attr in TCM_ATTR_PROC_LIST")?;
                    let value_bytes = nla.value();
                    if value_bytes.len() < 4 {
                        continue;
                    }
                    let mut value_arr = [0u8; 4];
                    value_arr.copy_from_slice(&value_bytes[..4]);
                    let value = i32::from_ne_bytes(value_arr);
                    match nla.kind() {
                        TCM_GENL_PROC_LIST_ATTR_PROC_ENTRY => procs.push(-value.abs()),
                        TCM_GENL_PROC_LIST_ATTR_PROC_TREE_ENTRY => procs.push(value.abs()),
                        _ => continue,
                    }
                }
                Ok(TcmAttr::ProcList(procs))
            }
            kind => Err(DecodeError::from(format!("unknown TCM attr: {kind}"))),
        }
    }
}
