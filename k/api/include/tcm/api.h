#ifndef TCM_NL_H
#define TCM_NL_H

#ifdef __KERNEL__
#include <linux/limits.h>
#include <linux/types.h>
#else
#include <limits.h>
#include <stdint.h>
#ifndef TCM_API_STD_TYPES_DEFINED
#define TCM_API_STD_TYPES_DEFINED
typedef uint8_t u8;
typedef int8_t s8;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
#endif /* TCM_API_STD_TYPES_DEFINED */
#endif /* __KERNEL__ */

#define TCM_GENL_FAMILY_NAME "tcm"
#define TCM_GENL_VERSION 1

/* genetlink 命令定义：前半部分为控制命令，后半部分为事件通道。 */
enum tcm_genl_cmd {
  TCM_GENL_CMD_UNSPEC = 0,
  __TCM_GENL_CMD_OPS_MIN,
  TCM_GENL_CMD_REGISTER,
  TCM_GENL_CMD_GET_FILE_STATS,
  TCM_GENL_CMD_FILE_WHITELIST_ADD,
  TCM_GENL_CMD_FILE_WHITELIST_REMOVE,
  __TCM_GENL_CMD_OPS_MAX,
  __TCM_GENL_CMD_EVENTS_MIN,
  TCM_GENL_CMD_FORK_RET_EVENT,
  TCM_GENL_CMD_FILE_EVENT,
  TCM_GENL_CMD_EXIT_EVENT,
  TCM_GENL_CMD_FILE_STATS_EVENT,
  __TCM_GENL_CMD_EVENTS_MAX,
};

/* 便捷宏：计算命令数量，避免手动维护。 */
#define TCM_GENL_CMD_OPS_COUNT                                                 \
  (__TCM_GENL_CMD_OPS_MAX - __TCM_GENL_CMD_OPS_MIN - 1)
#define TCM_GENL_CMD_EVENTS_COUNT                                              \
  (__TCM_GENL_CMD_EVENTS_MAX - __TCM_GENL_CMD_EVENTS_MIN - 1)
#define TCM_GENL_CMD_COUNT (TCM_GENL_CMD_OPS_COUNT + TCM_GENL_CMD_EVENTS_COUNT)

/* genetlink 属性定义，与用户态通信的字段必须保持同步。 */
enum tcm_genl_attr {
  TCM_GENL_ATTR_UNSPEC,
  TCM_GENL_ATTR_PARENT_PID,
  TCM_GENL_ATTR_CHILD_PID,
  TCM_GENL_ATTR_PARENT_PATH,
  TCM_GENL_ATTR_CHILD_PATH,
  TCM_GENL_ATTR_FILE_PID,
  TCM_GENL_ATTR_FILE_FD,
  TCM_GENL_ATTR_FILE_PATH,
  TCM_GENL_ATTR_FILE_OPERATION,
  TCM_GENL_ATTR_EXIT_PID,
  TCM_GENL_ATTR_EXIT_CODE,
  TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE,
  TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT,
  TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT,
  TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT,
  TCM_GENL_ATTR_FILE_STATS_TOP_PIDS,
  TCM_GENL_ATTR_CLIENT_PID,
  TCM_GENL_ATTR_FILE_WHITELIST_PATH,
  TCM_GENL_ATTR_MAX,
};

/* genetlink 多播组。 */
enum tcm_genl_mcgrp {
  TCM_GENL_MCGRP_HOOK,
  TCM_GENL_MCGRP_COUNT,
};
#define TCM_GENL_MCGRP_HOOK_NAME "hook"

/* 事件类型使用显式宽度，保证 netlink 属性长度确定。 */
typedef u8 file_event_type_msg_t;

enum tcm_file_event_type_value {
  FILE_EVENT_TYPE_UNSPEC = 0,
  FILE_EVENT_TYPE_OPEN = 1,
  FILE_EVENT_TYPE_WRITE = 2,
  FILE_EVENT_TYPE_CLOSE = 3,
};

/* fork 返回事件，仅包含父子进程 PID。 */
typedef struct {
  s32 parent_pid;
  s32 child_pid;
} fork_ret_event_msg_t;

/* 文件操作事件，包含进程、文件描述符与路径。 */
typedef struct {
  s32 pid;
  s32 fd;
  file_event_type_msg_t operation;
  char path[PATH_MAX];
} file_event_msg_t;

/* 进程退出事件。 */
typedef struct {
  s32 pid;
  s32 code;
} exit_event_t;

/* 监听器内部沿用无 _msg 后缀的别名，便于复用。 */
typedef fork_ret_event_msg_t fork_ret_event_t;
typedef file_event_msg_t file_event_t;

#endif /* TCM_NL_H */
