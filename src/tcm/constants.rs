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

const_u8_from_module!(#[allow(dead_code)] pub(crate) tcm_genl_cmd::TCM_GENL_CMD_UNSPEC);
const_u8_from_module!(pub(crate) tcm_genl_cmd::TCM_GENL_CMD_FORK_RET_EVENT);
const_u8_from_module!(pub(crate) tcm_genl_cmd::TCM_GENL_CMD_FILE_EVENT);
const_u8_from_module!(pub(crate) tcm_genl_cmd::TCM_GENL_CMD_EXIT_EVENT);
const_u8_from_module!(pub(crate) tcm_genl_cmd::TCM_GENL_CMD_FILE_STATS_EVENT);

pub(crate) const TCM_GENL_OP_REGISTER: u8 = bindings::tcm_genl_cmd::TCM_GENL_CMD_REGISTER as u8;
pub(crate) const TCM_GENL_OP_GET_FILE_STATS: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_GET_FILE_STATS as u8;
pub(crate) const TCM_GENL_OP_FILE_WHITELIST_ADD: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_FILE_WHITELIST_ADD as u8;
pub(crate) const TCM_GENL_OP_FILE_WHITELIST_REMOVE: u8 =
    bindings::tcm_genl_cmd::TCM_GENL_CMD_FILE_WHITELIST_REMOVE as u8;

const_u16_from_module!(#[allow(dead_code)] pub(crate) tcm_genl_attr::TCM_GENL_ATTR_UNSPEC);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PARENT_PID);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_CHILD_PID);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_PARENT_PATH);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_CHILD_PATH);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_PID);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_FD);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_PATH);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_OPERATION);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_EXIT_PID);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_EXIT_CODE);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_STATS_TOP_PIDS);
const_u16_from_module!(#[allow(dead_code)] pub(crate) tcm_genl_attr::TCM_GENL_ATTR_CLIENT_PID);
const_u16_from_module!(pub(crate) tcm_genl_attr::TCM_GENL_ATTR_FILE_WHITELIST_PATH);
