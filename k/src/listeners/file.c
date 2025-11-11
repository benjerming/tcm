#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "tcm/common.h"
#include "tcm/kprobe.h"
#include "tcm/listeners/file.h"
#include "tcm/whitelist/pid.h"

#define FILE_FIRST_SEEN_PID_HASH_BITS 8
#define FILE_FIRST_SEEN_FILE_HASH_BITS 8

struct file_first_seen_entry {
  file_event_type_t event;
  dev_t dev;
  unsigned long ino;
  struct hlist_node node;
};

struct file_first_seen_pid_entry {
  pid_t tgid;
  spinlock_t lock;
  struct hlist_node node;
  struct hlist_head files[1 << FILE_FIRST_SEEN_FILE_HASH_BITS];
  u32 file_count;
};

struct file_listener {
  struct tcm_kretprobe_handle *open_handle;
  struct tcm_kprobe_handle *write_handle;
  struct tcm_kprobe_handle *close_handle;
  struct tcm_kprobe_handle *exit_handle;
  struct workqueue_struct *wq;
  file_event_callback_t callback;
  void *callback_user_data;
  spinlock_t first_seen_lock;
  struct hlist_head first_seen_by_pid[1 << FILE_FIRST_SEEN_PID_HASH_BITS];
  atomic_t pending_work;
};

typedef struct {
  struct work_struct work;
  file_listener_t *listener;
  struct file *file;
  file_event_t event;
} file_event_work_t;

static inline struct hlist_head *
file_listener_pid_bucket(file_listener_t *listener, pid_t pid) {
  return &listener->first_seen_by_pid[hash_min((u32)pid,
                                               FILE_FIRST_SEEN_PID_HASH_BITS)];
}

static inline struct hlist_head *
file_listener_file_bucket(struct file_first_seen_pid_entry *pid_entry,
                          dev_t dev, unsigned long ino,
                          file_event_type_t event) {
  u64 dev64 = (u64)dev;
  u64 ino64 = (u64)ino;
  u32 hash = (u32)dev64;

  hash ^= (u32)(dev64 >> 32);
  hash ^= (u32)ino64;
  hash ^= (u32)(ino64 >> 32);
  hash ^= ((u32)event) << 24;

  return &pid_entry->files[hash_min(hash, FILE_FIRST_SEEN_FILE_HASH_BITS)];
}

static inline struct file_first_seen_pid_entry *
file_listener_find_pid_entry_locked(file_listener_t *listener, pid_t pid) {
  struct file_first_seen_pid_entry *entry;
  struct hlist_head *bucket;

  bucket = file_listener_pid_bucket(listener, pid);
  hlist_for_each_entry(entry, bucket, node) {
    if (entry->tgid == pid) {
      return entry;
    }
  }
  return NULL;
}

static struct file_first_seen_pid_entry *
file_listener_alloc_pid_entry(pid_t pid) {
  struct file_first_seen_pid_entry *pid_entry;

  pid_entry = kzalloc(sizeof(*pid_entry), GFP_ATOMIC);
  if (!pid_entry) {
    return NULL;
  }

  pid_entry->tgid = pid;
  spin_lock_init(&pid_entry->lock);
  hash_init(pid_entry->files);
  pid_entry->file_count = 0;

  return pid_entry;
}

static inline void
file_listener_put_pid_entry(struct file_first_seen_pid_entry *pid_entry) {
  if (pid_entry) {
    spin_unlock(&pid_entry->lock);
  }
}

static void
file_listener_free_pid_entry(struct file_first_seen_pid_entry *pid_entry) {
  if (!pid_entry) {
    return;
  }

  kfree(pid_entry);
}

static struct file_first_seen_pid_entry *
file_listener_get_or_create_pid_entry(file_listener_t *listener, pid_t pid) {
  struct file_first_seen_pid_entry *pid_entry;
  struct file_first_seen_pid_entry *new_entry = NULL;
  struct hlist_head *bucket;

  spin_lock(&listener->first_seen_lock);
  pid_entry = file_listener_find_pid_entry_locked(listener, pid);
  if (!pid_entry) {
    spin_unlock(&listener->first_seen_lock);

    new_entry = file_listener_alloc_pid_entry(pid);
    if (!new_entry) {
      return NULL;
    }

    spin_lock(&listener->first_seen_lock);
    pid_entry = file_listener_find_pid_entry_locked(listener, pid);
    if (!pid_entry) {
      bucket = file_listener_pid_bucket(listener, pid);
      hlist_add_head(&new_entry->node, bucket);
      pid_entry = new_entry;
      new_entry = NULL;
    }
  }

  spin_lock(&pid_entry->lock);
  spin_unlock(&listener->first_seen_lock);

  if (new_entry) {
    file_listener_free_pid_entry(new_entry);
  }

  return pid_entry;
}

static struct file_first_seen_pid_entry *
file_listener_get_pid_entry(file_listener_t *listener, pid_t pid) {
  struct file_first_seen_pid_entry *pid_entry;

  spin_lock(&listener->first_seen_lock);
  pid_entry = file_listener_find_pid_entry_locked(listener, pid);
  if (!pid_entry) {
    spin_unlock(&listener->first_seen_lock);
    return NULL;
  }

  spin_lock(&pid_entry->lock);
  spin_unlock(&listener->first_seen_lock);

  return pid_entry;
}

static bool file_listener_mark_first_seen(file_listener_t *listener, pid_t pid,
                                          file_event_type_t event,
                                          struct file *file) {
  struct file_first_seen_entry *entry;
  struct file_first_seen_entry *new_entry;
  struct file_first_seen_pid_entry *pid_entry;
  struct hlist_head *bucket;
  struct inode *inode;
  dev_t dev;
  unsigned long ino;

  if (!listener) {
    return false;
  }

  if (!file) {
    return true;
  }

  inode = file_inode(file);
  if (!inode) {
    return true;
  }

  dev = inode->i_sb ? inode->i_sb->s_dev : 0;
  ino = inode->i_ino;

  pid_entry = file_listener_get_or_create_pid_entry(listener, pid);
  if (!pid_entry) {
    pr_warn("%s: failed to allocate pid entry for pid %d\n", __func__, pid);
    return true;
  }

  bucket = file_listener_file_bucket(pid_entry, dev, ino, event);
  hlist_for_each_entry(entry, bucket, node) {
    if (entry->event == event && entry->dev == dev && entry->ino == ino) {
      file_listener_put_pid_entry(pid_entry);
      return false;
    }
  }

  new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC);
  if (!new_entry) {
    pr_warn("%s: failed to allocate first_seen entry for pid %d\n", __func__,
            pid);
    file_listener_put_pid_entry(pid_entry);
    return true;
  }

  new_entry->event = event;
  new_entry->dev = dev;
  new_entry->ino = ino;
  INIT_HLIST_NODE(&new_entry->node);

  hlist_add_head(&new_entry->node, bucket);
  pid_entry->file_count++;

  file_listener_put_pid_entry(pid_entry);

  return true;
}

static void file_listener_unmark_first_seen(file_listener_t *listener,
                                            pid_t pid, file_event_type_t event,
                                            struct file *file) {
  struct file_first_seen_entry *entry;
  struct hlist_node *tmp;
  struct hlist_head *bucket;
  struct file_first_seen_pid_entry *pid_entry;
  struct inode *inode;
  dev_t dev;
  unsigned long ino;
  bool remove_pid_entry = false;

  if (!listener || !file) {
    return;
  }

  inode = file_inode(file);
  if (!inode) {
    return;
  }

  dev = inode->i_sb ? inode->i_sb->s_dev : 0;
  ino = inode->i_ino;

  pid_entry = file_listener_get_pid_entry(listener, pid);
  if (!pid_entry) {
    return;
  }

  bucket = file_listener_file_bucket(pid_entry, dev, ino, event);
  hlist_for_each_entry_safe(entry, tmp, bucket, node) {
    if (entry->event != event || entry->dev != dev || entry->ino != ino) {
      continue;
    }
    hash_del(&entry->node);
    kfree(entry);
    if (pid_entry->file_count > 0) {
      pid_entry->file_count--;
    }
    if (!pid_entry->file_count) {
      remove_pid_entry = true;
    }
    break;
  }

  if (!remove_pid_entry) {
    file_listener_put_pid_entry(pid_entry);
    return;
  }

  file_listener_put_pid_entry(pid_entry);

  spin_lock(&listener->first_seen_lock);
  pid_entry = file_listener_find_pid_entry_locked(listener, pid);
  if (pid_entry) {
    spin_lock(&pid_entry->lock);
    if (!pid_entry->file_count) {
      hlist_del(&pid_entry->node);
      spin_unlock(&listener->first_seen_lock);
      spin_unlock(&pid_entry->lock);
      file_listener_free_pid_entry(pid_entry);
      return;
    }
    spin_unlock(&pid_entry->lock);
  }
  spin_unlock(&listener->first_seen_lock);
}

static void file_listener_reset_first_seen(file_listener_t *listener) {
  struct file_first_seen_pid_entry *pid_entry;
  struct hlist_node *tmp_pid;
  unsigned int bkt_pid;
  struct file_first_seen_entry *entry;
  struct hlist_node *tmp_file;
  unsigned int bkt_file;

  if (!listener) {
    return;
  }

  spin_lock(&listener->first_seen_lock);
  hash_for_each_safe(listener->first_seen_by_pid, bkt_pid, tmp_pid, pid_entry,
                     node) {
    hlist_del(&pid_entry->node);

    spin_lock(&pid_entry->lock);
    spin_unlock(&listener->first_seen_lock);

    hash_for_each_safe(pid_entry->files, bkt_file, tmp_file, entry, node) {
      hash_del(&entry->node);
      kfree(entry);
      if (pid_entry->file_count > 0) {
        pid_entry->file_count--;
      }
    }

    pid_entry->file_count = 0;
    spin_unlock(&pid_entry->lock);
    file_listener_free_pid_entry(pid_entry);

    spin_lock(&listener->first_seen_lock);
  }
  spin_unlock(&listener->first_seen_lock);
}

static void file_listener_remove_first_seen_pid(file_listener_t *listener,
                                                pid_t pid) {
  struct file_first_seen_pid_entry *pid_entry;
  struct file_first_seen_entry *entry;
  struct hlist_node *tmp;
  unsigned int bkt;

  if (!listener) {
    return;
  }

  spin_lock(&listener->first_seen_lock);
  pid_entry = file_listener_find_pid_entry_locked(listener, pid);
  if (!pid_entry) {
    spin_unlock(&listener->first_seen_lock);
    return;
  }

  spin_lock(&pid_entry->lock);
  hlist_del(&pid_entry->node);
  spin_unlock(&listener->first_seen_lock);

  hash_for_each_safe(pid_entry->files, bkt, tmp, entry, node) {
    hash_del(&entry->node);
    kfree(entry);
    if (pid_entry->file_count > 0) {
      pid_entry->file_count--;
    }
  }

  pid_entry->file_count = 0;
  spin_unlock(&pid_entry->lock);
  file_listener_free_pid_entry(pid_entry);
}

static void file_event_resolve_path(struct file *file, char *buf,
                                    size_t buflen) {
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
  file_event_work_t *event_work = container_of(work, file_event_work_t, work);
  file_listener_t *listener = event_work->listener;

  if (!event_work) {
    pr_warn("%s: event_work is NULL\n", __func__);
    return;
  }

  if (!listener) {
    pr_warn("%s: listener is NULL\n", __func__);
    return;
  }

  if (!event_work->file) {
    pr_warn("%s: file is NULL\n", __func__);
    return;
  }

  file_event_resolve_path(event_work->file, event_work->event.path,
                          sizeof(event_work->event.path));
  fput(event_work->file);
  event_work->file = NULL;

  listener->callback(&event_work->event, listener->callback_user_data);
  atomic_dec(&listener->pending_work);

  kfree(event_work);
}

// listener && listener->callback && listener->wq must be non-NULL
static int queue_file_event(file_listener_t *listener,
                            file_event_type_t operation, int fd,
                            struct file *file) {
  file_event_work_t *work;
  pid_t pid;

  if (!listener) {
    pr_warn("%s: listener is NULL\n", __func__);
    return -EINVAL;
  }

  if (!listener->callback) {
    pr_warn("%s: callback is NULL\n", __func__);
    return -EINVAL;
  }

  if (!listener->wq) {
    pr_warn("%s: wq is NULL\n", __func__);
    return -EINVAL;
  }

  if (!file) {
    pr_warn("%s: file is NULL\n", __func__);
    return -EINVAL;
  }

  // the tgid is the real pid of the process
  pid = task_tgid_nr(current);

  if (pid_whitelist_contains(pid)) {
    if (file) {
      fput(file);
    }
    return 0;
  }

  if (!file_listener_mark_first_seen(listener, pid, operation, file)) {
    if (file) {
      fput(file);
    }
    return 0;
  }

  work = kzalloc(sizeof(file_event_work_t), GFP_ATOMIC);
  if (!work) {
    file_listener_unmark_first_seen(listener, pid, operation, file);
    if (file) {
      fput(file);
    }
    pr_warn("%s: failed to allocate file_event_work\n", __func__);
    return -ENOMEM;
  }

  INIT_WORK(&work->work, file_event_workfn);
  work->listener = listener;
  work->file = file;
  work->event.pid = pid;
  work->event.fd = fd;
  work->event.operation = operation;
  work->event.path[0] = '\0';

  if (!queue_work(listener->wq, &work->work)) {
    file_listener_unmark_first_seen(listener, pid, operation, file);
    if (file) {
      fput(file);
    }
    kfree(work);
    pr_warn("%s: failed to queue file_event_work\n", __func__);
    return -EBUSY;
  }
  atomic_inc(&listener->pending_work);

  return 0;
}

static int exit_kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
  file_listener_t *listener;
  pid_t pid;

  if (!thread_group_leader(current)) {
    return 0;
  }

  listener = tcm_kprobe_get_user_data(kp);
  if (!listener) {
    return 0;
  }

  pid = task_tgid_nr(current);
  if (pid <= 0) {
    return 0;
  }

  file_listener_remove_first_seen_pid(listener, pid);
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

  listener = tcm_kretprobe_get_user_data(rp);
  if (!listener) {
    return 0;
  }

  if (!listener->callback) {
    return 0;
  }

  if (!listener->wq) {
    return 0;
  }

  fd = regs_return_value(regs);
  if (fd < 0) {
    return 0;
  }

  file = fget(fd);
  if (!file) {
    return 0;
  }

  queue_file_event(listener, FILE_EVENT_TYPE_OPEN, fd, file);
  return 0;
}

static int file_write_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
  file_listener_t *listener;
  int fd = -1;
  struct file *file = NULL;

  listener = tcm_kprobe_get_user_data(kp);
  if (!listener) {
    return 0;
  }

  if (!listener->callback) {
    return 0;
  }

  if (!listener->wq) {
    return 0;
  }

#ifdef CONFIG_X86_64
  fd = (int)regs->di;
#else
  pr_debug("%s: unsupported architecture\n", __func__);
  return 0;
#endif

  file = fget(fd);
  if (!file) {
    return 0;
  }

  queue_file_event(listener, FILE_EVENT_TYPE_WRITE, fd, file);
  return 0;
}

static int file_close_pre_handler(struct kprobe *kp, struct pt_regs *regs) {
  file_listener_t *listener;
  int fd = -1;
  struct file *file = NULL;

  listener = tcm_kprobe_get_user_data(kp);
  if (!listener) {
    return 0;
  }

  if (!listener->callback) {
    return 0;
  }

  if (!listener->wq) {
    return 0;
  }

#ifdef CONFIG_X86_64
  fd = (int)regs->di;
#else
  pr_debug("%s: unsupported architecture\n", __func__);
  return 0;
#endif
  file = fget(fd);
  if (!file) {
    return 0;
  }

  queue_file_event(listener, FILE_EVENT_TYPE_CLOSE, fd, file);
  return 0;
}

static int register_open_probe(file_listener_t *listener) {
  const struct tcm_kretprobe_config config = {
      .handler = file_open_ret_handler,
      .entry_handler = NULL,
      .maxactive = 64,
      .data_size = 0,
      .user_data = listener,
  };

  return tcm_kretprobe_register(TCM_KRETPROBE_TARGET_FILE_OPEN, &config,
                                &listener->open_handle);
}

static int register_write_probe(file_listener_t *listener) {
  const struct tcm_kprobe_config config = {
      .pre_handler = file_write_pre_handler,
      .user_data = listener,
  };

  return tcm_kprobe_register(TCM_KPROBE_TARGET_FILE_WRITE, &config,
                             &listener->write_handle);
}

static int register_close_probe(file_listener_t *listener) {
  const struct tcm_kprobe_config config = {
      .pre_handler = file_close_pre_handler,
      .user_data = listener,
  };

  return tcm_kprobe_register(TCM_KPROBE_TARGET_FILE_CLOSE, &config,
                             &listener->close_handle);
}

static int register_exit_probe(file_listener_t *listener) {
  const struct tcm_kprobe_config config = {
      .pre_handler = exit_kprobe_pre_handler,
      .user_data = listener,
  };
  return tcm_kprobe_register(TCM_KPROBE_TARGET_DO_EXIT, &config,
                             &listener->exit_handle);
}

int file_listener_init(file_listener_t **listener,
                       file_event_callback_t callback,
                       void *callback_user_data) {
  pr_info("%s\n", __func__);

  if (!listener) {
    pr_warn("  %s: listener is NULL\n", __func__);
    return -EINVAL;
  }

  if (*listener) {
    pr_info("  %s: file listener already initialized\n", __func__);
    return 0;
  }

  *listener = kzalloc(sizeof(file_listener_t), GFP_KERNEL);
  if (!*listener) {
    pr_warn("  %s: failed to kmalloc file listener\n", __func__);
    return -ENOMEM;
  }

  spin_lock_init(&(*listener)->first_seen_lock);
  hash_init((*listener)->first_seen_by_pid);

  struct workqueue_struct *wq;

  wq = alloc_workqueue("tcm_file_events", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
  if (!wq) {
    pr_err("  %s: failed to create workqueue\n", __func__);
    file_listener_exit(listener);
    return -ENOMEM;
  }
  (*listener)->wq = wq;
  atomic_set(&(*listener)->pending_work, 0);
  (*listener)->callback_user_data = callback_user_data;
  (*listener)->callback = callback;

  int ret = register_exit_probe(*listener);
  if (ret) {
    pr_err("%s: failed to register exit kprobe: %d\n", __func__, ret);
    file_listener_exit(listener);
    return ret;
  }

  ret = register_open_probe(*listener);
  if (ret) {
    pr_err("  %s: failed to register open kretprobe: %d\n", __func__, ret);
    file_listener_exit(listener);
    return ret;
  }

  ret = register_write_probe(*listener);
  if (ret) {
    pr_err("  %s: failed to register write kprobe: %d\n", __func__, ret);
    file_listener_exit(listener);
    return ret;
  }

  ret = register_close_probe(*listener);
  if (ret) {
    pr_err("  %s: failed to register close kprobe: %d\n", __func__, ret);
    file_listener_exit(listener);
    return ret;
  }

  pr_info("  %s: success\n", __func__);

  return 0;
}

int file_listener_get_stats(file_listener_t *listener,
                            file_listener_stats_t *stats) {
  struct file_first_seen_pid_entry *pid_entry;
  unsigned int bkt;
  u32 pid_entry_count = 0;
  u32 file_entry_count = 0;

  if (!listener || !stats) {
    return -EINVAL;
  }

  stats->top_pid_count = 0;
  memset(stats->top_pids, 0, sizeof(stats->top_pids));

  spin_lock(&listener->first_seen_lock);
  hash_for_each(listener->first_seen_by_pid, bkt, pid_entry, node) {
    pid_entry_count++;
    spin_lock(&pid_entry->lock);
    file_entry_count += pid_entry->file_count;

    if (pid_entry->file_count) {
      file_listener_pid_stat_t stat = {
          .pid = pid_entry->tgid,
          .file_count = pid_entry->file_count,
      };
      int insert_idx = -1;

      if (stats->top_pid_count < FILE_LISTENER_TOP_PID_LIMIT) {
        insert_idx = stats->top_pid_count;
        stats->top_pids[insert_idx] = stat;
        stats->top_pid_count++;
      } else {
        file_listener_pid_stat_t *last =
            &stats->top_pids[stats->top_pid_count - 1];
        if (stat.file_count > last->file_count ||
            (stat.file_count == last->file_count && stat.pid < last->pid)) {
          insert_idx = stats->top_pid_count - 1;
          stats->top_pids[insert_idx] = stat;
        }
      }

      if (insert_idx >= 0) {
        int i = insert_idx;
        while (i > 0) {
          file_listener_pid_stat_t *prev = &stats->top_pids[i - 1];
          file_listener_pid_stat_t *curr = &stats->top_pids[i];
          bool should_swap =
              curr->file_count > prev->file_count ||
              (curr->file_count == prev->file_count && curr->pid < prev->pid);
          if (!should_swap) {
            break;
          }
          file_listener_pid_stat_t tmp = *prev;
          *prev = *curr;
          *curr = tmp;
          i--;
        }
      }
    }

    spin_unlock(&pid_entry->lock);
  }
  spin_unlock(&listener->first_seen_lock);

  stats->pid_table_size = 1 << FILE_FIRST_SEEN_PID_HASH_BITS;
  stats->pid_entry_count = pid_entry_count;
  stats->file_entry_count = file_entry_count;

  return 0;
}

void file_listener_dump_stats(file_listener_t *listener) {
  file_listener_stats_t stats;

  if (!listener) {
    pr_warn("%s: file listener not initialized\n", __func__);
    return;
  }

  if (file_listener_get_stats(listener, &stats)) {
    pr_warn("%s: failed to collect file listener stats\n", __func__);
    return;
  }

  pr_info(
      "file_listener stats: pid_table_size=%u pid_entries=%u file_entries=%u "
      "top_pid_count=%u\n",
      stats.pid_table_size, stats.pid_entry_count, stats.file_entry_count,
      stats.top_pid_count);

  if (!stats.top_pid_count) {
    pr_info("  no active processes tracked\n");
    return;
  }

  for (u32 i = 0; i < stats.top_pid_count; i++) {
    pr_info("  top_pid[%u]: pid=%d file_count=%u\n", i, stats.top_pids[i].pid,
            stats.top_pids[i].file_count);
  }
}

void file_listener_exit(file_listener_t **listener) {
  if (!listener) {
    pr_warn("%s: invalid file listener\n", __func__);
    return;
  }

  if (!*listener) {
    pr_warn("%s: file listener not initialized\n", __func__);
    return;
  }

  pr_info("%s\n", __func__);

  tcm_kretprobe_unregister(&(*listener)->open_handle);
  tcm_kprobe_unregister(&(*listener)->write_handle);
  tcm_kprobe_unregister(&(*listener)->close_handle);
  tcm_kprobe_unregister(&(*listener)->exit_handle);

  if ((*listener)->wq) {
    pr_info("  %s: flushing workqueue, pending_work=%u\n", __func__,
            atomic_read(&(*listener)->pending_work));
    flush_workqueue((*listener)->wq);
    pr_info("  %s: flushed\n", __func__);

    destroy_workqueue((*listener)->wq);
    (*listener)->wq = NULL;
  }

  (*listener)->callback = NULL;
  (*listener)->callback_user_data = NULL;

  file_listener_reset_first_seen(*listener);

  kfree(*listener);
  *listener = NULL;
}
