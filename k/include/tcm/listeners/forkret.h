#ifndef TCM_LISTENERS_FORK_H
#define TCM_LISTENERS_FORK_H

#include "tcm/api.h"

/* fork/clone 结束事件的回调签名。 */
typedef void (*fork_ret_event_callback_t)(const fork_ret_event_t *event,
                                          void *user_data);
typedef struct fork_ret_listener fork_ret_listener_t;
int fork_ret_listener_init(fork_ret_listener_t **listener,
                           fork_ret_event_callback_t callback,
                           void *callback_user_data);
void fork_ret_listener_exit(fork_ret_listener_t **listener);

#endif /* TCM_LISTENERS_FORK_H */
