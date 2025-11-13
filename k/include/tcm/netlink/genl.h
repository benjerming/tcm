#ifndef TCM_NETLINK_GENL_H
#define TCM_NETLINK_GENL_H

#include "tcm/api.h"

struct file_listener;

typedef struct genl_core genl_core_t;
int genl_core_init(genl_core_t **core);
void genl_core_exit(genl_core_t **core);
int genl_core_set_file_listener(genl_core_t *core,
                                struct file_listener *listener);

void genl_core_on_exit_event(const exit_event_t *event, void *user_data);
void genl_core_on_file_event(const file_event_msg_t *event, void *user_data);
void genl_core_on_fork_ret_event(const fork_ret_event_msg_t *event,
                                 void *user_data);

#endif /* TCM_NETLINK_GENL_H */
