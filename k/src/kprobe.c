#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "tcm/kprobe.h"

struct tcm_kprobe_handle {
  struct kprobe kp;
  bool registered;
  void *user_data;
};

struct tcm_kretprobe_handle {
  struct kretprobe krp;
  bool registered;
  void *user_data;
};

struct tcm_kprobe_target_info {
  const char *const *targets;
  size_t count;
};

struct tcm_kretprobe_target_info {
  const char *const *targets;
  size_t count;
};

static const char *const tcm_kprobe_file_write_targets[] = {
    "__x64_sys_write",
    "ksys_write",
};

static const char *const tcm_kprobe_file_close_targets[] = {
    "__x64_sys_close",
    "ksys_close",
};

static const char *const tcm_kprobe_do_exit_targets[] = {
    "do_exit",
};

static const struct tcm_kprobe_target_info
    tcm_kprobe_target_table[TCM_KPROBE_TARGET_COUNT] = {
        [TCM_KPROBE_TARGET_FILE_WRITE] =
            {
                .targets = tcm_kprobe_file_write_targets,
                .count = ARRAY_SIZE(tcm_kprobe_file_write_targets),
            },
        [TCM_KPROBE_TARGET_FILE_CLOSE] =
            {
                .targets = tcm_kprobe_file_close_targets,
                .count = ARRAY_SIZE(tcm_kprobe_file_close_targets),
            },
        [TCM_KPROBE_TARGET_DO_EXIT] =
            {
                .targets = tcm_kprobe_do_exit_targets,
                .count = ARRAY_SIZE(tcm_kprobe_do_exit_targets),
            },
};

static const char *const tcm_kretprobe_file_open_targets[] = {
    "do_sys_openat2",
    "ksys_openat",
    "__x64_sys_openat",
    "__ia32_sys_openat",
};

static const char *const tcm_kretprobe_fork_clone_targets[] = {
    "kernel_clone",
    "__do_sys_clone",
    "__x64_sys_clone",
};

static const struct tcm_kretprobe_target_info
    tcm_kretprobe_target_table[TCM_KRETPROBE_TARGET_COUNT] = {
        [TCM_KRETPROBE_TARGET_FILE_OPEN] =
            {
                .targets = tcm_kretprobe_file_open_targets,
                .count = ARRAY_SIZE(tcm_kretprobe_file_open_targets),
            },
        [TCM_KRETPROBE_TARGET_FORK_CLONE] =
            {
                .targets = tcm_kretprobe_fork_clone_targets,
                .count = ARRAY_SIZE(tcm_kretprobe_fork_clone_targets),
            },
};

static int
tcm_kprobe_register_targets_internal(struct tcm_kprobe_handle *handle,
                                     const char *const *targets,
                                     size_t target_count) {
  struct kprobe *kp;
  size_t i;
  int ret;
  int final_ret = -ENOENT;

  if (!handle || !targets || target_count == 0) {
    pr_warn("%s: invalid arguments\n", __func__);
    return -EINVAL;
  }

  kp = &handle->kp;
  handle->registered = false;

  for (i = 0; i < target_count; ++i) {
    const char *target = targets[i];
    if (!target) {
      continue;
    }

    kp->symbol_name = target;
    kp->addr = NULL;

    ret = register_kprobe(kp);
    if (ret == 0) {
      handle->registered = true;
      pr_info("  %s: registered kprobe on %s\n", __func__, target);
      return 0;
    }

    if (ret == -ENOENT) {
      pr_info("  %s: symbol %s not found\n", __func__, target);
    } else {
      final_ret = ret;
      pr_warn("  %s: register_kprobe(%s) failed: %d\n", __func__, target, ret);
    }
  }

  kp->symbol_name = NULL;
  kp->addr = NULL;

  return final_ret;
}

int tcm_kprobe_register(enum tcm_kprobe_target target,
                        const struct tcm_kprobe_config *config,
                        struct tcm_kprobe_handle **handle) {
  const struct tcm_kprobe_target_info *info;
  struct tcm_kprobe_handle *value;
  int ret;

  if (!handle) {
    pr_warn("%s: invalid arguments\n", __func__);
    return -EINVAL;
  }

  if (*handle) {
    pr_warn("%s: handle already initialized\n", __func__);
    return -EALREADY;
  }

  if (!config) {
    pr_warn("%s: invalid config\n", __func__);
    return -EINVAL;
  }

  if (target < 0 || target >= TCM_KPROBE_TARGET_COUNT) {
    pr_warn("%s: invalid kprobe target %d\n", __func__, target);
    return -EINVAL;
  }

  info = &tcm_kprobe_target_table[target];
  if (!info->targets || info->count == 0) {
    pr_warn("%s: empty target table for %d\n", __func__, target);
    return -ENOENT;
  }

  value = kzalloc(sizeof(*value), GFP_KERNEL);
  if (!value) {
    pr_warn("%s: failed to allocate kprobe handle\n", __func__);
    return -ENOMEM;
  }

  value->kp.pre_handler = config->pre_handler;
  value->kp.post_handler = config->post_handler;
  value->user_data = config->user_data;

  ret = tcm_kprobe_register_targets_internal(value, info->targets, info->count);
  if (ret) {
    kfree(value);
    return ret;
  }

  *handle = value;
  return 0;
}

void tcm_kprobe_unregister(struct tcm_kprobe_handle **handle) {
  struct tcm_kprobe_handle *value;

  if (!handle || !*handle) {
    return;
  }

  value = *handle;

  if (value->registered) {
    unregister_kprobe(&value->kp);
    value->registered = false;
  }

  value->kp.symbol_name = NULL;
  value->kp.addr = NULL;
  value->kp.pre_handler = NULL;
  value->kp.post_handler = NULL;
  value->user_data = NULL;

  kfree(value);
  *handle = NULL;
}

void *tcm_kprobe_get_user_data(const struct kprobe *kp) {
  struct tcm_kprobe_handle *handle;

  if (!kp) {
    return NULL;
  }

  handle = container_of((struct kprobe *)kp, struct tcm_kprobe_handle, kp);
  return handle->user_data;
}

static int tcm_kretprobe_register_targets_internal(
    struct tcm_kretprobe_handle *handle,
    const struct tcm_kretprobe_config *config, const char *const *targets,
    size_t target_count) {
  struct kretprobe *krp;
  size_t i;
  int ret;
  int final_ret = -ENOENT;

  if (!handle || !targets || target_count == 0) {
    pr_warn("%s: invalid arguments\n", __func__);
    return -EINVAL;
  }

  krp = &handle->krp;
  handle->registered = false;

  for (i = 0; i < target_count; ++i) {
    const char *target = targets[i];
    if (!target) {
      continue;
    }

    krp->handler = config->handler;
    krp->entry_handler = config->entry_handler;
    krp->maxactive = config->maxactive;
    krp->data_size = config->data_size;
    krp->nmissed = 0;

    krp->kp.symbol_name = target;
    krp->kp.addr = NULL;

    ret = register_kretprobe(krp);
    if (ret == 0) {
      handle->registered = true;
      pr_info("  %s: registered kretprobe on %s\n", __func__, target);
      return 0;
    }

    if (ret == -ENOENT) {
      pr_info("  %s: symbol %s not found\n", __func__, target);
    } else {
      final_ret = ret;
      pr_warn("  %s: register_kretprobe(%s) failed: %d\n", __func__, target,
              ret);
    }
  }

  krp->kp.symbol_name = NULL;
  krp->kp.addr = NULL;
  krp->handler = NULL;
  krp->entry_handler = NULL;
  krp->maxactive = 0;
  krp->data_size = 0;

  return final_ret;
}

int tcm_kretprobe_register(enum tcm_kretprobe_target target,
                           const struct tcm_kretprobe_config *config,
                           struct tcm_kretprobe_handle **handle) {
  const struct tcm_kretprobe_target_info *info;
  struct tcm_kretprobe_handle *value;
  int ret;

  if (!handle) {
    pr_warn("%s: invalid arguments\n", __func__);
    return -EINVAL;
  }

  if (*handle) {
    pr_warn("%s: handle already initialized\n", __func__);
    return -EALREADY;
  }

  if (!config) {
    pr_warn("%s: invalid config\n", __func__);
    return -EINVAL;
  }

  if (!config->handler) {
    pr_warn("%s: missing kretprobe handler\n", __func__);
    return -EINVAL;
  }

  if (config->maxactive <= 0) {
    pr_warn("%s: invalid maxactive %d\n", __func__, config->maxactive);
    return -EINVAL;
  }

  if (target < 0 || target >= TCM_KRETPROBE_TARGET_COUNT) {
    pr_warn("%s: invalid kretprobe target %d\n", __func__, target);
    return -EINVAL;
  }

  info = &tcm_kretprobe_target_table[target];
  if (!info->targets || info->count == 0) {
    pr_warn("%s: empty target table for %d\n", __func__, target);
    return -ENOENT;
  }

  value = kzalloc(sizeof(*value), GFP_KERNEL);
  if (!value) {
    pr_warn("%s: failed to allocate kretprobe handle\n", __func__);
    return -ENOMEM;
  }

  value->user_data = config->user_data;

  ret = tcm_kretprobe_register_targets_internal(value, config, info->targets,
                                                info->count);
  if (ret) {
    kfree(value);
    return ret;
  }

  *handle = value;
  return 0;
}

void tcm_kretprobe_unregister(struct tcm_kretprobe_handle **handle) {
  struct tcm_kretprobe_handle *value;

  if (!handle || !*handle) {
    return;
  }

  value = *handle;

  if (value->registered) {
    unregister_kretprobe(&value->krp);
    value->registered = false;
  }

  value->krp.kp.symbol_name = NULL;
  value->krp.kp.addr = NULL;
  value->krp.handler = NULL;
  value->krp.entry_handler = NULL;
  value->krp.maxactive = 0;
  value->krp.data_size = 0;
  value->user_data = NULL;

  kfree(value);
  *handle = NULL;
}

void *tcm_kretprobe_get_user_data(const struct kretprobe *krp) {
  struct tcm_kretprobe_handle *handle;

  if (!krp) {
    return NULL;
  }

  handle =
      container_of((struct kretprobe *)krp, struct tcm_kretprobe_handle, krp);
  return handle->user_data;
}
