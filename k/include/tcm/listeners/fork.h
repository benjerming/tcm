#ifndef TCM_LISTENERS_FORK_H
#define TCM_LISTENERS_FORK_H

#include "tcm/netlink/genl.h"

typedef struct fork_listener fork_listener_t;
typedef void (*fork_event_callback_t)(const fork_event_t *event, void *user_data);
int init_fork_listener(fork_listener_t **listener, fork_event_callback_t callback, void *user_data);
void free_fork_listener(fork_listener_t **listener);

typedef struct fork_ret_listener fork_ret_listener_t;
typedef void (*fork_ret_event_callback_t)(const fork_ret_event_t *event, void *user_data);
int init_fork_ret_listener(fork_ret_listener_t **listener, fork_ret_event_callback_t callback, void *user_data);
void free_fork_ret_listener(fork_ret_listener_t **listener);

#endif /* TCM_LISTENERS_FORK_H */
