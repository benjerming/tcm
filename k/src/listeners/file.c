#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "tcm/listeners/file.h"

struct file_event_work {
  struct work_struct work;
  file_listener_t *listener;
  struct file *file;
  file_event_t event;
};

struct file_listener {
  struct kretprobe open_kretprobe;
  struct kprobe write_kprobe;
  struct kprobe close_kprobe;
  struct workqueue_struct *wq;
  file_event_callback_t callback;
  void *callback_user_data;
  bool open_registered;
  bool write_registered;
  bool close_registered;
};

static void file_event_resolve_path(struct file *file, char *buf, size_t buflen) {
  char *path;

  if (!buf || buflen == 0) {
    return;
  }

  buf[0] = '\0';
  if (!file) {
    return;
  }

  path = d_path(&file->f_path, buf, buflen);
  if (IS_ERR(path)) {
    buf[0] = '\0';
    return;
  }

  if (path != buf) {
    size_t len = strnlen(path, buflen - 1);
    memmove(buf, path, len);
    buf[len] = '\0';
  }
}

static void file_event_workfn(struct work_struct *work) {
  struct file_event_work *event_work =
      container_of(work, struct file_event_work, work);
  file_listener_t *listener = event_work->listener;

  if (event_work->file) {
    file_event_resolve_path(event_work->file, event_work->event.path,
                            sizeof(event_work->event.path));
    fput(event_work->file);
    event_work->file = NULL;
  }

  if (listener && listener->callback) {
    listener->callback(&event_work->event, listener->callback_user_data);
  }

  kfree(event_work);
}

static int queue_file_event(file_listener_t *listener, file_event_type_t operation,
                            int fd, u64 bytes, struct file *file) {
  struct file_event_work *work;

  if (!listener) {
    if (file) {
      fput(file);
    }
    return -EINVAL;
  }

  if (!listener->wq) {
    if (file) {
      fput(file);
    }
    return -EINVAL;
  }

  work = kmalloc(sizeof(*work), GFP_ATOMIC);
  if (!work) {
    if (file) {
      fput(file);
    }
    pr_warn("%s: failed to allocate file_event_work\n", __func__);
    return -ENOMEM;
  }

  INIT_WORK(&work->work, file_event_workfn);
  work->listener = listener;
  work->file = file;
  work->event.pid = task_pid_nr(current);
  work->event.fd = fd;
  work->event.operation = operation;
  work->event.bytes = bytes;
  work->event.path[0] = '\0';

  if (!queue_work(listener->wq, &work->work)) {
    if (file) {
      fput(file);
    }
    kfree(work);
    pr_warn("%s: failed to queue file_event_work\n", __func__);
    return -EBUSY;
  }

  return 0;
}

static int file_open_ret_handler(struct kretprobe_instance *ri,
                                 struct pt_regs *regs) {
  struct kretprobe *rp = get_kretprobe(ri);
  file_listener_t *listener;
  long fd;
  struct file *file = NULL;

  if (!rp) {
    return 0;
  }

  listener = container_of(rp, file_listener_t, open_kretprobe);
  if (unlikely(!listener) || !listener->callback) {
    return 0;
  }

  fd = regs_return_value(regs);
  if (fd < 0) {
    return 0;
  }

  file = fget(fd);
  queue_file_event(listener, FILE_EVENT_TYPE_OPEN, fd, 0, file);
  return 0;
}

static int file_write_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
  file_listener_t *listener;
  int fd = -1;
  size_t count = 0;
  struct file *file = NULL;

  listener = container_of(kp, file_listener_t, write_kprobe);
  if (unlikely(!listener) || !listener->callback) {
    return 0;
  }

#ifdef CONFIG_X86_64
  fd = (int)regs->di;
  count = (size_t)regs->dx;
#else
  pr_debug("%s: unsupported architecture\n", __func__);
  return 0;
#endif

  if (fd >= 0) {
    file = fget(fd);
  }

  queue_file_event(listener, FILE_EVENT_TYPE_WRITE, fd, count, file);
  return 0;
}

static int file_close_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
  file_listener_t *listener;
  int fd = -1;
  struct file *file = NULL;

  listener = container_of(kp, file_listener_t, close_kprobe);
  if (unlikely(!listener) || !listener->callback) {
    return 0;
  }

#ifdef CONFIG_X86_64
  fd = (int)regs->di;
#else
  pr_debug("%s: unsupported architecture\n", __func__);
  return 0;
#endif
  if (fd >= 0) {
    file = fget(fd);
  }

  queue_file_event(listener, FILE_EVENT_TYPE_CLOSE, fd, 0, file);
  return 0;
}

static void reset_open_kretprobe(file_listener_t *listener) {
  listener->open_kretprobe.kp.symbol_name = NULL;
  listener->open_kretprobe.kp.addr = NULL;
  listener->open_kretprobe.handler = file_open_ret_handler;
  listener->open_kretprobe.entry_handler = NULL;
  listener->open_kretprobe.maxactive = 64;
  listener->open_kretprobe.data_size = 0;
}

static int register_open_probe(file_listener_t *listener) {
  static const char *const targets[] = {
      "do_sys_openat2",
      "ksys_openat",
      "__x64_sys_openat",
      "__ia32_sys_openat",
  };
  int ret;
  size_t i;

  reset_open_kretprobe(listener);

  for (i = 0; i < ARRAY_SIZE(targets); ++i) {
    listener->open_kretprobe.kp.symbol_name = targets[i];
    listener->open_kretprobe.kp.addr = NULL;
    ret = register_kretprobe(&listener->open_kretprobe);
    if (ret == 0) {
      pr_info("  %s: registered open kretprobe on %s\n", __func__, targets[i]);
      listener->open_registered = true;
      return 0;
    } else if (ret == -ENOENT) {
      pr_info("  %s: symbol %s not found\n", __func__, targets[i]);
    } else {
      pr_warn("  %s: register_kretprobe(%s) failed: %d\n", __func__,
              targets[i], ret);
    }
  }

  listener->open_kretprobe.kp.symbol_name = NULL;
  listener->open_kretprobe.kp.addr = NULL;
  return -ENOENT;
}

static int register_write_probe(file_listener_t *listener) {
  static const char *const targets[] = {
      "__x64_sys_write",
      "ksys_write",
  };
  int ret;
  size_t i;

  memset(&listener->write_kprobe, 0, sizeof(listener->write_kprobe));
  listener->write_kprobe.pre_handler = file_write_pre_handler;

  for (i = 0; i < ARRAY_SIZE(targets); ++i) {
    listener->write_kprobe.symbol_name = targets[i];
    listener->write_kprobe.addr = NULL;
    ret = register_kprobe(&listener->write_kprobe);
    if (ret == 0) {
      pr_info("  %s: registered write kprobe on %s\n", __func__, targets[i]);
      listener->write_registered = true;
      return 0;
    } else if (ret == -ENOENT) {
      pr_info("  %s: symbol %s not found\n", __func__, targets[i]);
    } else {
      pr_warn("  %s: register_kprobe(%s) failed: %d\n", __func__, targets[i],
              ret);
    }
  }

  listener->write_kprobe.symbol_name = NULL;
  listener->write_kprobe.addr = NULL;
  return -ENOENT;
}

static int register_close_probe(file_listener_t *listener) {
  static const char *const targets[] = {
      "__x64_sys_close",
      "ksys_close",
  };
  int ret;
  size_t i;

  memset(&listener->close_kprobe, 0, sizeof(listener->close_kprobe));
  listener->close_kprobe.pre_handler = file_close_pre_handler;

  for (i = 0; i < ARRAY_SIZE(targets); ++i) {
    listener->close_kprobe.symbol_name = targets[i];
    listener->close_kprobe.addr = NULL;
    ret = register_kprobe(&listener->close_kprobe);
    if (ret == 0) {
      pr_info("  %s: registered close kprobe on %s\n", __func__, targets[i]);
      listener->close_registered = true;
      return 0;
    } else if (ret == -ENOENT) {
      pr_info("  %s: symbol %s not found\n", __func__, targets[i]);
    } else {
      pr_warn("  %s: register_kprobe(%s) failed: %d\n", __func__, targets[i],
              ret);
    }
  }

  listener->close_kprobe.symbol_name = NULL;
  listener->close_kprobe.addr = NULL;
  return -ENOENT;
}

int init_file_listener(file_listener_t **listener, file_event_callback_t callback,
                       void *user_data) {
  int ret;

  pr_info("%s\n", __func__);

  if (!listener) {
    pr_warn("%s: invalid listener pointer\n", __func__);
    return -EINVAL;
  }

  if (*listener) {
    pr_warn("%s: listener already initialized\n", __func__);
    return -EALREADY;
  }

  *listener = kzalloc(sizeof(**listener), GFP_KERNEL);
  if (!*listener) {
    pr_warn("%s: failed to allocate listener\n", __func__);
    return -ENOMEM;
  }

  (*listener)->callback = callback;
  (*listener)->callback_user_data = user_data;

  (*listener)->wq =
      alloc_workqueue("tcm_file_events", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
  if (!(*listener)->wq) {
    pr_err("%s: failed to create workqueue\n", __func__);
    ret = -ENOMEM;
    goto error;
  }

  ret = register_open_probe(*listener);
  if (ret) {
    pr_err("%s: failed to register open kretprobe: %d\n", __func__, ret);
    goto error;
  }

  ret = register_write_probe(*listener);
  if (ret) {
    pr_err("%s: failed to register write kprobe: %d\n", __func__, ret);
    goto error;
  }

  ret = register_close_probe(*listener);
  if (ret) {
    pr_err("%s: failed to register close kprobe: %d\n", __func__, ret);
    goto error;
  }

  return 0;

error:
  free_file_listener(listener);
  return ret;
}

void free_file_listener(file_listener_t **listener) {
  file_listener_t *value;

  if (!listener) {
    pr_warn("%s: invalid listener pointer\n", __func__);
    return;
  }

  if (!*listener) {
    return;
  }

  value = *listener;

  pr_info("%s\n", __func__);

  if (value->open_registered) {
    unregister_kretprobe(&value->open_kretprobe);
    value->open_registered = false;
  }

  if (value->write_registered) {
    unregister_kprobe(&value->write_kprobe);
    value->write_registered = false;
  }

  if (value->close_registered) {
    unregister_kprobe(&value->close_kprobe);
    value->close_registered = false;
  }

  if (value->wq) {
    flush_workqueue(value->wq);
    destroy_workqueue(value->wq);
    value->wq = NULL;
  }

  value->callback = NULL;
  value->callback_user_data = NULL;

  kfree(value);
  *listener = NULL;
}

