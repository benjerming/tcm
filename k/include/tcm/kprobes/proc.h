#ifndef TCM_KPROBES_PROC_H
#define TCM_KPROBES_PROC_H

#include "tcm/api.h"

/* fork/clone 结束事件的回调签名。 */
typedef void (*proc_event_callback_t)(const proc_event_t *event,
                                      void *user_data);
typedef struct proc_listener proc_listener_t;
int proc_listener_init(proc_listener_t **listener,
                       proc_event_callback_t callback,
                       void *callback_user_data);
void proc_listener_exit(proc_listener_t **listener);

#endif /* TCM_KPROBES_PROC_H */
