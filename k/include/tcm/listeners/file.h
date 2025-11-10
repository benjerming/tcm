#ifndef TCM_LISTENERS_FILE_H
#define TCM_LISTENERS_FILE_H

#include "tcm/netlink/genl.h"

typedef struct file_listener file_listener_t;
typedef void (*file_event_callback_t)(const file_event_t *event,
                                      void *user_data);

int init_file_listener(file_listener_t **listener,
                       file_event_callback_t callback, void *user_data);
void free_file_listener(file_listener_t **listener);

#endif /* TCM_LISTENERS_FILE_H */
