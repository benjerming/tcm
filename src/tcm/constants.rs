pub const TCM_GENL_FAMILY_NAME: &str = "tcm";
pub const TCM_GENL_MCGRP_NAME: &str = "hook";
pub const TCM_GENL_FAMILY_VERSION: u8 = 1;

#[allow(dead_code)]
pub(crate) const TCM_GENL_CMD_UNSPEC: u8 = 0;
pub(crate) const TCM_GENL_CMD_FORK_RET_EVENT: u8 = 1;
pub(crate) const TCM_GENL_CMD_FILE_EVENT: u8 = 2;
pub(crate) const TCM_GENL_CMD_EXIT_EVENT: u8 = 3;
pub(crate) const TCM_GENL_CMD_FILE_STATS_EVENT: u8 = 4;

pub(crate) const TCM_GENL_OP_REGISTER: u8 = 0;
pub(crate) const TCM_GENL_OP_GET_FILE_STATS: u8 = 1;

#[allow(dead_code)]
pub(crate) const TCM_GENL_ATTR_UNSPEC: u16 = 0;
pub(crate) const TCM_GENL_ATTR_PARENT_PID: u16 = 1;
pub(crate) const TCM_GENL_ATTR_CHILD_PID: u16 = 2;
pub(crate) const TCM_GENL_ATTR_PARENT_PATH: u16 = 3;
pub(crate) const TCM_GENL_ATTR_CHILD_PATH: u16 = 4;
pub(crate) const TCM_GENL_ATTR_FILE_PID: u16 = 5;
pub(crate) const TCM_GENL_ATTR_FILE_FD: u16 = 6;
pub(crate) const TCM_GENL_ATTR_FILE_PATH: u16 = 7;
pub(crate) const TCM_GENL_ATTR_FILE_OPERATION: u16 = 8;
pub(crate) const TCM_GENL_ATTR_EXIT_PID: u16 = 9;
pub(crate) const TCM_GENL_ATTR_EXIT_CODE: u16 = 10;
pub(crate) const TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE: u16 = 11;
pub(crate) const TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT: u16 = 12;
pub(crate) const TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT: u16 = 13;
pub(crate) const TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT: u16 = 14;
pub(crate) const TCM_GENL_ATTR_FILE_STATS_TOP_PIDS: u16 = 15;
#[allow(dead_code)]
pub(crate) const TCM_GENL_ATTR_CLIENT_PID: u16 = 16;
