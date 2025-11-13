#ifndef TCM_LISTENERS_EXIT_H
#define TCM_LISTENERS_EXIT_H

#include "tcm/api.h"

/* 退出事件回调类型：向上层报告 PID 与退出码。 */
typedef void (*exit_event_callback_t)(const exit_event_t *event,
                                      void *user_data);
typedef struct exit_listener exit_listener_t;
int exit_listener_init(exit_listener_t **listener,
                       exit_event_callback_t callback,
                       void *callback_user_data);
void exit_listener_exit(exit_listener_t **listener);

#endif /* TCM_LISTENERS_EXIT_H */
