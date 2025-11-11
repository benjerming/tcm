#ifndef TCM_NETLINK_GENL_H
#define TCM_NETLINK_GENL_H

#include <linux/limits.h>
#include <linux/types.h>

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
  char path[PATH_MAX];
} file_event_t;

typedef struct {
  pid_t pid;
  s32 code;
} exit_event_t;

struct file_listener;

typedef struct genl_core genl_core_t;
int genl_core_init(genl_core_t **core);
void genl_core_exit(genl_core_t **core);
int genl_core_set_file_listener(genl_core_t *core, struct file_listener *listener);

void genl_core_on_exit_event(const exit_event_t *event, void *user_data);
void genl_core_on_file_event(const file_event_t *event, void *user_data);
void genl_core_on_fork_ret_event(const fork_ret_event_t *event,
                                 void *user_data);

#endif /* TCM_NETLINK_GENL_H */