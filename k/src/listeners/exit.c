#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/workqueue.h>

#include "tcm/kprobe.h"
#include "tcm/listeners/exit.h"

/*
 * 退出事件监听器：
 *  - 通过 kprobe 挂钩 do_exit，捕获进程退出信息
 *  - 将 PID 与退出码回调给上层，用于清理资源或统计
 */

struct exit_listener {
  struct tcm_kprobe_handle *handle;
  exit_event_callback_t callback;
  void *callback_user_data;
};

/* kprobe 回调：确保仅在线程组长退出时上报事件。 */
static int exit_kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
  exit_listener_t *listener;
  exit_event_t event;

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

  event.pid = (s32)task_tgid_nr(current);
  event.code = (s32)regs->di;

  listener->callback(&event, listener->callback_user_data);
  return 0;
}

/* 初始化退出监听器并注册 do_exit kprobe。 */
int exit_listener_init(exit_listener_t **listener,
                       exit_event_callback_t callback,
                       void *callback_user_data) {
  pr_info("%s\n", __func__);
  if (!listener) {
    pr_warn("  %s: listener is NULL\n", __func__);
    return -EINVAL;
  }

  if (*listener) {
    pr_info("  %s: exit listener already initialized\n", __func__);
    return 0;
  }

  *listener = kzalloc(sizeof(exit_listener_t), GFP_KERNEL);
  if (!*listener) {
    pr_warn("  %s: failed to kmalloc exit listener\n", __func__);
    return -ENOMEM;
  }

  (*listener)->callback_user_data = callback_user_data;
  (*listener)->callback = callback;

  const struct tcm_kprobe_config config = {
      .pre_handler = exit_kprobe_pre_handler,
      .user_data = *listener,
  };

  int ret = tcm_kprobe_register(TCM_KPROBE_TARGET_DO_EXIT, &config,
                                &(*listener)->handle);
  if (ret) {
    pr_err("  %s: failed to register kprobe: %d\n", __func__, ret);
    exit_listener_exit(listener);
    return ret;
  }

  pr_info("  %s: success\n", __func__);
  return 0;
}

/* 注销监听器并释放资源。 */
void exit_listener_exit(exit_listener_t **listener) {
  if (!listener) {
    pr_warn("%s: invalid exit listener\n", __func__);
    return;
  }

  if (!*listener) {
    pr_warn("%s: exit listener not initialized\n", __func__);
    return;
  }

  pr_info("%s\n", __func__);

  tcm_kprobe_unregister(&(*listener)->handle);

  (*listener)->callback = NULL;
  (*listener)->callback_user_data = NULL;

  kfree(*listener);
  *listener = NULL;
}
