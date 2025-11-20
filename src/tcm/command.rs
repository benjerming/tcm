use crate::tcm::constants::*;
use netlink_packet_core::DecodeError;
use std::convert::TryFrom;

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
    TrustFileAdd,
    TrustFileRemove,
    TrustProcAdd,
    TrustProcRemove,
}

impl From<TcmOperateCmd> for u8 {
    fn from(op: TcmOperateCmd) -> u8 {
        match op {
            TcmOperateCmd::Login => TCM_GENL_OP_LOGIN,
            TcmOperateCmd::GetFileStats => TCM_GENL_OP_GET_FILE_STATS,
            TcmOperateCmd::TrustFileAdd => TCM_GENL_OP_TRUST_FILE_ADD,
            TcmOperateCmd::TrustFileRemove => TCM_GENL_OP_TRUST_FILE_REMOVE,
            TcmOperateCmd::TrustProcAdd => TCM_GENL_OP_TRUST_PROC_ADD,
            TcmOperateCmd::TrustProcRemove => TCM_GENL_OP_TRUST_PROC_REMOVE,
        }
    }
}

impl TryFrom<u8> for TcmOperateCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TCM_GENL_OP_LOGIN => Ok(TcmOperateCmd::Login),
            TCM_GENL_OP_GET_FILE_STATS => Ok(TcmOperateCmd::GetFileStats),
            TCM_GENL_OP_TRUST_FILE_ADD => Ok(TcmOperateCmd::TrustFileAdd),
            TCM_GENL_OP_TRUST_FILE_REMOVE => Ok(TcmOperateCmd::TrustFileRemove),
            TCM_GENL_OP_TRUST_PROC_ADD => Ok(TcmOperateCmd::TrustProcAdd),
            TCM_GENL_OP_TRUST_PROC_REMOVE => Ok(TcmOperateCmd::TrustProcRemove),
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
            TCM_GENL_OP_TRUST_FILE_ADD => Ok(TcmCommand::Operation(TcmOperateCmd::TrustFileAdd)),
            TCM_GENL_OP_TRUST_FILE_REMOVE => {
                Ok(TcmCommand::Operation(TcmOperateCmd::TrustFileRemove))
            }
            TCM_GENL_OP_TRUST_PROC_ADD => Ok(TcmCommand::Operation(TcmOperateCmd::TrustProcAdd)),
            TCM_GENL_OP_TRUST_PROC_REMOVE => {
                Ok(TcmCommand::Operation(TcmOperateCmd::TrustProcRemove))
            }
            TCM_GENL_CMD_PROC_EVENT => Ok(TcmCommand::Event(TcmEventCmd::ProcEvent)),
            TCM_GENL_CMD_FILE_EVENT => Ok(TcmCommand::Event(TcmEventCmd::FileEvent)),
            TCM_GENL_CMD_FILE_STATS_EVENT => Ok(TcmCommand::Event(TcmEventCmd::FileStatsEvent)),
            _ => Err(DecodeError::from(format!("unknown TCM command: {value}"))),
        }
    }
}
