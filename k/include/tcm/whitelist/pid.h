#ifndef TCM_WHITELIST_FILE_PID_H
#define TCM_WHITELIST_FILE_PID_H

#include <linux/sched.h>
#include <linux/types.h>

int pid_whitelist_add(pid_t pid);
bool pid_whitelist_contains(pid_t pid);

#endif /* TCM_WHITELIST_FILE_PID_H */
