use std::convert::TryFrom;

use netlink_packet_core::DecodeError;

use crate::tcm::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmEventCmd {
    FileEvent,
    ProcEvent,
    FileStatsEvent,
}

impl From<TcmEventCmd> for u8 {
    fn from(cmd: TcmEventCmd) -> u8 {
        match cmd {
            TcmEventCmd::FileEvent => TCM_GENL_CMD_FILE_EVENT,
            TcmEventCmd::ProcEvent => TCM_GENL_CMD_PROC_EVENT,
            TcmEventCmd::FileStatsEvent => TCM_GENL_CMD_FILE_STATS_EVENT,
        }
    }
}

impl TryFrom<u8> for TcmEventCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TCM_GENL_CMD_PROC_EVENT => Ok(TcmEventCmd::ProcEvent),
            TCM_GENL_CMD_FILE_EVENT => Ok(TcmEventCmd::FileEvent),
            TCM_GENL_CMD_FILE_STATS_EVENT => Ok(TcmEventCmd::FileStatsEvent),
            other => Err(DecodeError::from(format!(
                "unknown TCM event command: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmOperateCmd {
    Login,
    GetFileStats,
    FileWhitelistAdd,
    FileWhitelistRemove,
    ProcWhitelistAdd,
    ProcWhitelistRemove,
}

impl From<TcmOperateCmd> for u8 {
    fn from(op: TcmOperateCmd) -> u8 {
        match op {
            TcmOperateCmd::Login => TCM_GENL_OP_LOGIN,
            TcmOperateCmd::GetFileStats => TCM_GENL_OP_GET_FILE_STATS,
            TcmOperateCmd::FileWhitelistAdd => TCM_GENL_OP_FILE_WHITELIST_ADD,
            TcmOperateCmd::FileWhitelistRemove => TCM_GENL_OP_FILE_WHITELIST_REMOVE,
            TcmOperateCmd::ProcWhitelistAdd => TCM_GENL_OP_PROC_WHITELIST_ADD,
            TcmOperateCmd::ProcWhitelistRemove => TCM_GENL_OP_PROC_WHITELIST_REMOVE,
        }
    }
}

impl TryFrom<u8> for TcmOperateCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TCM_GENL_OP_LOGIN => Ok(TcmOperateCmd::Login),
            TCM_GENL_OP_GET_FILE_STATS => Ok(TcmOperateCmd::GetFileStats),
            TCM_GENL_OP_FILE_WHITELIST_ADD => Ok(TcmOperateCmd::FileWhitelistAdd),
            TCM_GENL_OP_FILE_WHITELIST_REMOVE => Ok(TcmOperateCmd::FileWhitelistRemove),
            TCM_GENL_OP_PROC_WHITELIST_ADD => Ok(TcmOperateCmd::ProcWhitelistAdd),
            TCM_GENL_OP_PROC_WHITELIST_REMOVE => Ok(TcmOperateCmd::ProcWhitelistRemove),
            other => Err(DecodeError::from(format!(
                "unknown TCM operation command: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmCommand {
    Event(TcmEventCmd),
    Operation(TcmOperateCmd),
}

impl From<TcmCommand> for u8 {
    fn from(cmd: TcmCommand) -> u8 {
        match cmd {
            TcmCommand::Event(event) => event.into(),
            TcmCommand::Operation(op) => op.into(),
        }
    }
}

impl TryFrom<u8> for TcmCommand {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TCM_GENL_OP_LOGIN => Ok(TcmCommand::Operation(TcmOperateCmd::Login)),
            TCM_GENL_OP_GET_FILE_STATS => Ok(TcmCommand::Operation(TcmOperateCmd::GetFileStats)),
            TCM_GENL_OP_FILE_WHITELIST_ADD => {
                Ok(TcmCommand::Operation(TcmOperateCmd::FileWhitelistAdd))
            }
            TCM_GENL_OP_FILE_WHITELIST_REMOVE => {
                Ok(TcmCommand::Operation(TcmOperateCmd::FileWhitelistRemove))
            }
            TCM_GENL_OP_PROC_WHITELIST_ADD => {
                Ok(TcmCommand::Operation(TcmOperateCmd::ProcWhitelistAdd))
            }
            TCM_GENL_OP_PROC_WHITELIST_REMOVE => {
                Ok(TcmCommand::Operation(TcmOperateCmd::ProcWhitelistRemove))
            }
            TCM_GENL_CMD_PROC_EVENT => Ok(TcmCommand::Event(TcmEventCmd::ProcEvent)),
            TCM_GENL_CMD_FILE_EVENT => Ok(TcmCommand::Event(TcmEventCmd::FileEvent)),
            TCM_GENL_CMD_FILE_STATS_EVENT => Ok(TcmCommand::Event(TcmEventCmd::FileStatsEvent)),
            _ => Err(DecodeError::from(format!("unknown TCM command: {value}"))),
        }
    }
}
