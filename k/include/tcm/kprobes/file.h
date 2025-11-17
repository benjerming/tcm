#ifndef TCM_LISTENERS_FILE_H
#define TCM_LISTENERS_FILE_H

#include "tcm/api.h"

/* 文件事件回调类型，用户态通过该回调收到筛选后的事件。 */
typedef void (*file_event_callback_t)(const file_event_t *event,
                                      void *user_data);
typedef struct file_listener file_listener_t;
/* 监听器生命周期接口：初始化时传入回调与上下文指针。 */
int file_listener_init(file_listener_t **listener,
                       file_event_callback_t callback,
                       void *callback_user_data);
void file_listener_exit(file_listener_t **listener);

#define FILE_LISTENER_TOP_PID_LIMIT 10

/* 单个进程的文件事件统计。 */
typedef struct {
  s32 pid;
  u32 file_count;
} file_listener_pid_stat_t;

/* 汇总统计信息，top_pids 按文件数降序排列。 */
typedef struct {
  u32 pid_table_size;
  u32 pid_entry_count;
  u32 file_entry_count;
  u32 top_pid_count;
  file_listener_pid_stat_t top_pids[FILE_LISTENER_TOP_PID_LIMIT];
} file_listener_stats_t;

int file_listener_get_stats(file_listener_t *listener,
                            file_listener_stats_t *stats);
void file_listener_dump_stats(file_listener_t *listener);

#endif /* TCM_LISTENERS_FILE_H */
