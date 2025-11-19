#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::CStr;

#[allow(dead_code)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/tcm_api.rs"));
}

fn cstr(bytes: &'static [u8]) -> &'static str {
    CStr::from_bytes_with_nul(bytes)
        .expect("TCM API strings must be null-terminated")
        .to_str()
        .expect("TCM API strings must be valid UTF-8")
}

pub fn genl_family_name() -> &'static str {
    cstr(bindings::TCM_GENL_FAMILY_NAME)
}

pub fn genl_mcgrp_name() -> &'static str {
    cstr(bindings::TCM_GENL_MCGRP_HOOK_NAME)
}

pub fn genl_family_version() -> u8 {
    bindings::TCM_GENL_VERSION as u8
}

macro_rules! const_u8_from_module {
    ($(#[$attr:meta])* $vis:vis $module:ident::$name:ident) => {
        $(#[$attr])*
        $vis const $name: u8 = bindings::$module::$name as u8;
    };
}

macro_rules! const_u16_from_module {
    ($(#[$attr:meta])* $vis:vis $module:ident::$name:ident) => {
        $(#[$attr])*
        $vis const $name: u16 = bindings::$module::$name as u16;
    };
}

const_u8_from_module!(pub(crate) tcm_genl_cmd::TCM_GENL_CMD_FILE_EVENT);
const_u8_from_module!(pub(crate) tcm_genl_cmd::TCM_GENL_CMD_PROC_EVENT);
const_u8_from_module!(pub(crate) tcm_genl_cmd::TCM_GENL_CMD_FILE_STATS_EVENT);

pub(crate) const TCM_GENL_OP_LOGIN: u8 = bindings::tcm_genl_cmd::TCM_GENL_CMD_LOGIN as u8;
pub(crate) const TCM_GENL_OP_GET_FILE_STATS: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_GET_FILE_STATS as u8;
pub(crate) const TCM_GENL_OP_FILE_WHITELIST_ADD: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_FILE_WHITELIST_ADD as u8;
pub(crate) const TCM_GENL_OP_FILE_WHITELIST_REMOVE: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_FILE_WHITELIST_REMOVE as u8;
pub(crate) const TCM_GENL_OP_PROC_WHITELIST_ADD: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_PROC_WHITELIST_ADD as u8;
pub(crate) const TCM_GENL_OP_PROC_WHITELIST_REMOVE: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_PROC_WHITELIST_REMOVE as u8;

pub(crate) const TCM_GENL_ATTR_KEY_MAX_LEN: usize = bindings::TCM_GENL_ATTR_KEY_MAX_LEN as usize;

const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FD);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_KEY);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PID);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PPID);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PATH1);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PATH2);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PATH_LIST);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PROC_LIST);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_EVENT_TYPE);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PROC_EVENT_TYPE);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_TOP_PIDS);
const_u16_from_module!(pub(crate) tcm_genl_path_list_attr::TCM_GENL_PATH_LIST_ATTR_FILE_ENTRY);
const_u16_from_module!(pub(crate) tcm_genl_proc_list_attr::TCM_GENL_PROC_LIST_ATTR_PROC_ENTRY);
const_u16_from_module!(pub(crate) tcm_genl_proc_list_attr::TCM_GENL_PROC_LIST_ATTR_PROC_TREE_ENTRY);
