#ifndef TCM_NETLINK_GENL_H
#define TCM_NETLINK_GENL_H

#include <linux/types.h>
#include <linux/limits.h>

typedef struct {
  pid_t parent_pid;
  pid_t child_pid;
  char parent_path[PATH_MAX];
  char child_path[PATH_MAX];
} fork_event_t;

typedef struct {
  pid_t parent_pid;
  pid_t child_pid;
} fork_ret_event_t;

typedef enum {
  FILE_EVENT_TYPE_UNSPEC = 0,
  FILE_EVENT_TYPE_OPEN = 1,
  FILE_EVENT_TYPE_WRITE = 2,
  FILE_EVENT_TYPE_CLOSE = 3,
} file_event_type_t;

typedef struct {
  pid_t pid;
  int fd;
  file_event_type_t operation;
  u64 bytes;
  char path[PATH_MAX];
} file_event_t;

typedef struct genl_core genl_core_t;
int init_genl_core(genl_core_t **gc);
void free_genl_core(genl_core_t **gc);

int genl_core_send_fork_event(genl_core_t *gc, const fork_event_t *event);
int genl_core_send_fork_ret_event(genl_core_t *gc, const fork_ret_event_t *event);
int genl_core_send_file_event(genl_core_t *gc, const file_event_t *event);

#endif /* TCM_NETLINK_GENL_H */