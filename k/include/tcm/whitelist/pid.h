#ifndef TCM_WHITELIST_FILE_PID_H
#define TCM_WHITELIST_FILE_PID_H

#include <linux/sched.h>
#include <linux/types.h>

/* 追加进程白名单，常用于忽略自有守护进程。 */
int pid_whitelist_add(pid_t pid);
/* 查询白名单，监听器会跳过这些 PID。 */
bool pid_whitelist_contains(pid_t pid);

#endif /* TCM_WHITELIST_FILE_PID_H */
