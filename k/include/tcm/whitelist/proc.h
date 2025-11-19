#ifndef TCM_WHITELIST_PROC_H
#define TCM_WHITELIST_PROC_H

#include <linux/sched.h>
#include <linux/types.h>

/* 追加进程白名单，常用于忽略自有守护进程。 */
int proc_whitelist_add(pid_t pid, bool include_children);
/* 将进程从白名单中移除。 */
int proc_whitelist_remove(pid_t pid, bool include_children);
/* 查询白名单，监听器会跳过这些 PID。 */
bool proc_whitelist_contains(pid_t pid);

#endif /* TCM_WHITELIST_PROC_H */
