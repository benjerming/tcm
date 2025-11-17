#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/limits.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "tcm/kprobes/core.h"
#include "tcm/kprobes/proc.h"

/*
 * fork/clone 返回事件监听器：
 *  - 通过 kretprobe 捕获 kernel_clone/clone 的返回值
 *  - 将父子进程 PID 组合上报给上层
 */

struct proc_listener {
  struct tcm_kretprobe_handle *handle;
  struct tcm_kprobe_handle *exit_handle;
  proc_event_callback_t callback;
  void *callback_user_data;
};

/* kretprobe handler：当 clone 成功返回时生成事件。 */
static int fork_ret_handler(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct kretprobe *rp = get_kretprobe(ri);
  if (!rp) {
    return 0;
  }

  proc_listener_t *listener = tcm_kretprobe_get_user_data(rp);
  if (unlikely(!listener)) {
    return 0;
  }

  if (!listener->callback) {
    return 0;
  }

  long child_pid = regs_return_value(regs);
  if (child_pid <= 0) {
    return 0;
  }

  proc_event_t event = {
      .type = PROC_EVENT_TYPE_FORK,
      .ppid = (s32)task_tgid_nr(current),
      .pid = (s32)child_pid,
  };

  listener->callback(&event, listener->callback_user_data);
  return 0;
}

/* kprobe 回调：确保仅在线程组长退出时上报事件。 */
static int exit_kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
  proc_listener_t *listener;

  if (!thread_group_leader(current)) {
    return 0;
  }

  listener = tcm_kprobe_get_user_data(kp);
  if (!listener) {
    return 0;
  }

  if (!listener->callback) {
    return 0;
  }

  proc_event_t event = {
      .type = PROC_EVENT_TYPE_EXIT,
      .ppid = (s32)task_ppid_nr(current),
      .pid = (s32)task_tgid_nr(current),
  };

  listener->callback(&event, listener->callback_user_data);
  return 0;
}

static int register_fork_ret_probe(proc_listener_t *listener) {
  const struct tcm_kretprobe_config config = {
      .handler = fork_ret_handler,
      .entry_handler = NULL,
      .maxactive = 32,
      .data_size = 0,
      .user_data = listener,
  };

  return tcm_kretprobe_register(TCM_KRETPROBE_TARGET_FORK_CLONE, &config,
                                &listener->handle);
}

static int register_exit_probe(proc_listener_t *listener) {
  const struct tcm_kprobe_config config = {
      .pre_handler = exit_kprobe_pre_handler,
      .user_data = listener,
  };
  return tcm_kprobe_register(TCM_KPROBE_TARGET_DO_EXIT, &config,
                             &listener->exit_handle);
}

/* 初始化 fork 返回监听器并注册对应 kretprobe。 */
int proc_listener_init(proc_listener_t **listener,
                       proc_event_callback_t callback,
                       void *callback_user_data) {
  pr_info("%s\n", __func__);

  if (!listener) {
    pr_warn("%s: listener is NULL\n", __func__);
    return -EINVAL;
  }

  if (*listener) {
    pr_info("%s: proc listener already initialized\n", __func__);
    return 0;
  }

  *listener = kzalloc(sizeof(proc_listener_t), GFP_KERNEL);
  if (!*listener) {
    pr_warn("%s: failed to kmalloc proc listener\n", __func__);
    return -ENOMEM;
  }

  (*listener)->callback_user_data = callback_user_data;
  (*listener)->callback = callback;

  int ret = register_fork_ret_probe(*listener);
  if (ret) {
    pr_err("  %s failed: register_fork_ret_probe error %d\n", __func__, ret);
    proc_listener_exit(listener);
    return ret;
  }

  ret = register_exit_probe(*listener);
  if (ret) {
    pr_err("  %s failed: register_exit_probe error %d\n", __func__, ret);
    proc_listener_exit(listener);
    return ret;
  }

  pr_info("  %s: success\n", __func__);

  return 0;
}

/* 注销 fork 返回监听器。 */
void proc_listener_exit(proc_listener_t **listener) {
  if (!listener) {
    pr_warn("%s: invalid fork ret listener\n", __func__);
    return;
  }

  if (!*listener) {
    pr_warn("%s: fork ret listener not initialized\n", __func__);
    return;
  }

  pr_info("%s\n", __func__);

  tcm_kretprobe_unregister(&(*listener)->handle);
  tcm_kprobe_unregister(&(*listener)->exit_handle);

  (*listener)->callback = NULL;
  (*listener)->callback_user_data = NULL;

  kfree(*listener);
  *listener = NULL;
}