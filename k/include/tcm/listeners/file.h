#ifndef TCM_LISTENERS_FILE_H
#define TCM_LISTENERS_FILE_H

#include "tcm/netlink/genl.h"

typedef void (*file_event_callback_t)(const file_event_t *event,
                                      void *user_data);
typedef struct file_listener file_listener_t;
int file_listener_init(file_listener_t **listener,
                       file_event_callback_t callback,
                       void *callback_user_data);
void file_listener_exit(file_listener_t **listener);

#define FILE_LISTENER_TOP_PID_LIMIT 10

typedef struct {
  pid_t pid;
  u32 file_count;
} file_listener_pid_stat_t;

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
