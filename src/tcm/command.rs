use std::convert::TryFrom;

use netlink_packet_core::DecodeError;

use super::constants::{
    TCM_GENL_CMD_EXIT_EVENT, TCM_GENL_CMD_FILE_EVENT, TCM_GENL_CMD_FILE_STATS_EVENT,
    TCM_GENL_CMD_FORK_RET_EVENT, TCM_GENL_OP_GET_FILE_STATS, TCM_GENL_OP_REGISTER,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmEventCmd {
    ForkRetEvent,
    FileEvent,
    ExitEvent,
    FileStatsEvent,
}

impl From<TcmEventCmd> for u8 {
    fn from(cmd: TcmEventCmd) -> u8 {
        match cmd {
            TcmEventCmd::ForkRetEvent => TCM_GENL_CMD_FORK_RET_EVENT,
            TcmEventCmd::FileEvent => TCM_GENL_CMD_FILE_EVENT,
            TcmEventCmd::ExitEvent => TCM_GENL_CMD_EXIT_EVENT,
            TcmEventCmd::FileStatsEvent => TCM_GENL_CMD_FILE_STATS_EVENT,
        }
    }
}

impl TryFrom<u8> for TcmEventCmd {
    type Error = DecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            TCM_GENL_CMD_FORK_RET_EVENT => Ok(TcmEventCmd::ForkRetEvent),
            TCM_GENL_CMD_FILE_EVENT => Ok(TcmEventCmd::FileEvent),
            TCM_GENL_CMD_EXIT_EVENT => Ok(TcmEventCmd::ExitEvent),
            TCM_GENL_CMD_FILE_STATS_EVENT => Ok(TcmEventCmd::FileStatsEvent),
            other => Err(DecodeError::from(format!(
                "unknown TCM event command: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmOp {
    Register,
    GetFileStats,
}

impl From<TcmOp> for u8 {
    fn from(op: TcmOp) -> u8 {
        match op {
            TcmOp::Register => TCM_GENL_OP_REGISTER,
            TcmOp::GetFileStats => TCM_GENL_OP_GET_FILE_STATS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcmCommand {
    Event(TcmEventCmd),
    Operation(TcmOp),
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
        if let Ok(event) = TcmEventCmd::try_from(value) {
            return Ok(TcmCommand::Event(event));
        }

        match value {
            TCM_GENL_OP_REGISTER => Ok(TcmCommand::Operation(TcmOp::Register)),
            TCM_GENL_OP_GET_FILE_STATS => Ok(TcmCommand::Operation(TcmOp::GetFileStats)),
            other => Err(DecodeError::from(format!("unknown TCM command: {other}"))),
        }
    }
}
