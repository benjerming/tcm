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

#include "tcm/kprobe.h"
#include "tcm/listeners/forkret.h"
#include "tcm/netlink/genl.h"

struct fork_ret_listener {
  struct tcm_kretprobe_handle *handle;
  fork_ret_event_callback_t callback;
  void *callback_user_data;
};

static int fork_ret_handler(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct kretprobe *rp = get_kretprobe(ri);
  if (!rp) {
    return 0;
  }

  fork_ret_listener_t *listener = tcm_kretprobe_get_user_data(rp);
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

  fork_ret_event_t event = {
      .parent_pid = task_tgid_nr(current),
      .child_pid = child_pid,
  };

  listener->callback(&event, listener->callback_user_data);
  return 0;
}

int fork_ret_listener_init(fork_ret_listener_t **listener,
                           fork_ret_event_callback_t callback,
                           void *callback_user_data) {
  pr_info("%s\n", __func__);

  if (!listener) {
    pr_warn("%s: listener is NULL\n", __func__);
    return -EINVAL;
  }

  if (*listener) {
    pr_info("%s: fork ret listener already initialized\n", __func__);
    return 0;
  }

  *listener = kzalloc(sizeof(fork_ret_listener_t), GFP_KERNEL);
  if (!*listener) {
    pr_warn("%s: failed to kmalloc fork ret listener\n", __func__);
    return -ENOMEM;
  }

  (*listener)->callback_user_data = callback_user_data;
  (*listener)->callback = callback;

  const struct tcm_kretprobe_config config = {
      .handler = fork_ret_handler,
      .entry_handler = NULL,
      .maxactive = 32,
      .data_size = 0,
      .user_data = *listener,
  };

  int ret = tcm_kretprobe_register(TCM_KRETPROBE_TARGET_FORK_CLONE, &config,
                                   &(*listener)->handle);
  if (ret) {
    if (ret == -ENOENT) {
      pr_err("  %s failed, no suitable symbol found for target %d\n", __func__,
             TCM_KRETPROBE_TARGET_FORK_CLONE);
    } else {
      pr_err("  %s failed: register_kretprobe error %d\n", __func__, ret);
    }
    fork_ret_listener_exit(listener);
    return ret;
  }

  return 0;
}

void fork_ret_listener_exit(fork_ret_listener_t **listener) {
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

  (*listener)->callback = NULL;
  (*listener)->callback_user_data = NULL;

  kfree(*listener);
  *listener = NULL;
}