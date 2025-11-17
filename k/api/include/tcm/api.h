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

#define TCM_GENL_ATTR_KEY_MAX_LEN 16

/* genetlink 命令定义：前半部分为控制命令，后半部分为事件通道。 */
enum tcm_genl_cmd {
  TCM_GENL_CMD_UNSPEC = 0,
  __TCM_GENL_CMD_OPS_MIN,
  TCM_GENL_CMD_LOGIN,
  TCM_GENL_CMD_GET_FILE_STATS,
  TCM_GENL_CMD_PROC_WHITELIST_ADD,
  TCM_GENL_CMD_PROC_WHITELIST_REMOVE,
  TCM_GENL_CMD_FILE_WHITELIST_ADD,
  TCM_GENL_CMD_FILE_WHITELIST_REMOVE,
  __TCM_GENL_CMD_OPS_MAX,
  __TCM_GENL_CMD_EVENTS_MIN,
  TCM_GENL_CMD_PROC_EVENT,
  TCM_GENL_CMD_FILE_EVENT,
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
  TCM_GENL_ATTR_FD,
  TCM_GENL_ATTR_PID,
  TCM_GENL_ATTR_PPID,
  TCM_GENL_ATTR_KEY,
  TCM_GENL_ATTR_PATH1,
  TCM_GENL_ATTR_PATH2,
  TCM_GENL_ATTR_FILE_EVENT_TYPE,
  TCM_GENL_ATTR_PROC_EVENT_TYPE,
  TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE,
  TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT,
  TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT,
  TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT,
  TCM_GENL_ATTR_FILE_STATS_TOP_PIDS,
  TCM_GENL_ATTR_MAX,
};

/* genetlink 多播组。 */
enum tcm_genl_mcgrp {
  TCM_GENL_MCGRP_HOOK,
  TCM_GENL_MCGRP_COUNT,
};
#define TCM_GENL_MCGRP_HOOK_NAME "hook"

/* 事件类型使用显式宽度，保证 netlink 属性长度确定。 */
typedef u8 file_event_type_t;

enum tcm_file_event_type_value {
  FILE_EVENT_TYPE_UNSPEC = 0,
  FILE_EVENT_TYPE_OPEN = 1,
  FILE_EVENT_TYPE_WRITE = 2,
  FILE_EVENT_TYPE_CLOSE = 3,
};

typedef u8 proc_event_type_t;

enum tcm_proc_event_type_value {
  PROC_EVENT_TYPE_UNSPEC = 0,
  PROC_EVENT_TYPE_FORK = 1,
  PROC_EVENT_TYPE_EXEC = 2,
  PROC_EVENT_TYPE_EXIT = 3,
};

/* fork 返回事件，仅包含父子进程 PID。 */
typedef struct {
  proc_event_type_t type;
  s32 pid;
  s32 ppid;
} proc_event_t;

/* 文件操作事件，包含进程、文件描述符与路径。 */
typedef struct {
  file_event_type_t type;
  s32 fd;
  s32 pid;
  char path[PATH_MAX];
} file_event_t;

#endif /* TCM_NL_H */
