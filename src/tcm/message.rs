use std::convert::TryFrom;

use netlink_packet_core::{DecodeError, Emitable, NlasIterator, Parseable, ParseableParametrized};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use super::attr::TcmAttr;
use super::command::{TcmCommand, TcmEventCmd};
use super::constants::{TCM_GENL_FAMILY_NAME, TCM_GENL_FAMILY_VERSION};
use super::events::FileListenerPidStat;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcmMessage {
    pub cmd: TcmCommand,
    pub nlas: Vec<TcmAttr>,
}

impl TcmMessage {
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

    pub fn parent_pid(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
            TcmAttr::ParentPid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_PARENT_PID"))
    }

    pub fn child_pid(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
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

    pub fn file_pid(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
            TcmAttr::FilePid(pid) => Some(*pid),
            _ => None,
        })
        .ok_or_else(|| DecodeError::from("missing TCM_ATTR_FILE_PID"))
    }

    pub fn file_fd(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
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

    pub fn exit_pid(&self) -> Result<u32, DecodeError> {
        self.find_u32(|attr| match attr {
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

impl GenlFamily for TcmMessage {
    fn family_name() -> &'static str {
        TCM_GENL_FAMILY_NAME
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }

    fn version(&self) -> u8 {
        TCM_GENL_FAMILY_VERSION
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
        let cmd = TcmCommand::try_from(header.cmd)?;
        let nlas = NlasIterator::new(payload)
            .map(|nla| nla.and_then(|nla| TcmAttr::parse(&nla)))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { cmd, nlas })
    }
}
