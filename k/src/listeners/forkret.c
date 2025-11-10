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

#include "tcm/listeners/fork.h"
#include "tcm/netlink/genl.h"

struct fork_ret_listener {
  struct kretprobe krp;
  fork_ret_event_callback_t callback;
  void *callback_user_data;
};

static int fork_ret_handler(struct kretprobe_instance *ri,
                            struct pt_regs *regs) {
  struct kretprobe *rp = get_kretprobe(ri);
  if (!rp) {
    return 0;
  }

  fork_ret_listener_t *listener = container_of(rp, fork_ret_listener_t, krp);
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
      .parent_pid = task_pid_nr(current),
      .child_pid = child_pid,
  };

  listener->callback(&event, listener->callback_user_data);
  return 0;
}

int init_fork_ret_listener(fork_ret_listener_t **listener,
                           fork_ret_event_callback_t callback,
                           void *user_data) {
  pr_info("%s\n", __func__);

  if (!listener) {
    pr_warn("%s: fork ret listener invalid pointer\n", __func__);
    return -EINVAL;
  }

  if (*listener) {
    pr_warn("%s: fork ret listener already initialized\n", __func__);
    return -EALREADY;
  }

  *listener = kmalloc(sizeof(fork_ret_listener_t), GFP_KERNEL);
  if (!*listener) {
    pr_warn("%s: fork ret listener kmalloc failed\n", __func__);
    return -ENOMEM;
  }

  (*listener)->callback = callback;
  (*listener)->callback_user_data = user_data;

  static const char *const targets[] = {
      "kernel_clone",
      "__do_sys_clone",
      "__x64_sys_clone",
  };
  int ret;
  size_t i;

  (*listener)->krp.handler = fork_ret_handler;
  (*listener)->krp.maxactive = 32;

  for (i = 0; i < ARRAY_SIZE(targets); ++i) {
    (*listener)->krp.kp.symbol_name = targets[i];
    (*listener)->krp.kp.addr = NULL;
    ret = register_kretprobe(&(*listener)->krp);
    if (ret == 0) {
      pr_info("  %s success, symbol=%s\n", __func__, targets[i]);
      return 0;
    } else if (ret == -ENOENT) {
      pr_info("  %s failed: symbol=%s errno=ENOENT\n", __func__, targets[i]);
    } else {
      pr_warn("  %s failed: symbol=%s errno=%d\n", __func__, targets[i], ret);
    }
  }

  (*listener)->krp.kp.symbol_name = NULL;
  (*listener)->krp.kp.addr = NULL;

  pr_err("  %s failed, no suitable symbol found\n", __func__);
  for (i = 0; i < ARRAY_SIZE(targets); ++i) {
    pr_err("    symbol=%s\n", targets[i]);
  }

  kfree(*listener);
  *listener = NULL;

  return -ENOENT;
}

void free_fork_ret_listener(fork_ret_listener_t **listener) {
  if (!listener) {
    pr_warn("%s: fork ret listener invalid pointer\n", __func__);
    return;
  }

  if (!*listener) {
    pr_warn("%s: fork ret listener already freed\n", __func__);
    return;
  }

  pr_info("%s\n", __func__);

  unregister_kretprobe(&(*listener)->krp);

  (*listener)->callback = NULL;
  (*listener)->callback_user_data = NULL;

  kfree(*listener);
  *listener = NULL;
}