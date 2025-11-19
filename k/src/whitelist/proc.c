#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/pid.h>
#include <linux/rbtree.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/threads.h>

#include "tcm/whitelist/proc.h"

/*
 * PROC 白名单：
 *  - 使用树结构模拟当前（添加时观察到的）进程树
 *  - 支持标记是否对子进程生效，默认继承
 *  - module_param 提供树形字符串表示，兼容旧的逗号列表
 */

#define PROC_WHITELIST_MAX_EXPLICIT 128
#define PROC_WHITELIST_PARAM_LEN 4096
#define PROC_WHITELIST_LINEAGE_MAX 64

struct proc_whitelist_node {
  pid_t pid;
  bool is_explicit;
  bool include_children;
  struct proc_whitelist_node *parent;
  struct rb_node rb;
  struct list_head sibling;
  struct list_head children;
};

struct proc_whitelist_parsed_node {
  pid_t pid;
  bool include_children;
  bool is_explicit;
  struct list_head sibling;
  struct list_head children;
};

static DEFINE_RWLOCK(g_rwlock);
static struct rb_root g_proc_whitelist_index = RB_ROOT;
static LIST_HEAD(g_proc_whitelist_roots);
static size_t g_proc_whitelist_explicit_count;
static size_t g_proc_whitelist_node_count;
static char g_proc_whitelist_raw[PROC_WHITELIST_PARAM_LEN];

/* 解析用户输入的 PID 列表，自动去重并限制数量。 */
static int parse_proc_list(char *input, pid_t *out, size_t max, size_t *count) {
  char *cursor;
  char *token;
  size_t idx = 0;

  if (!out || !count || !input) {
    return -EINVAL;
  }

  cursor = input;

  while ((token = strsep(&cursor, ", \t")) != NULL) {
    long value;
    int ret;
    bool exists = false;
    size_t i;

    if (*token == '\0') {
      continue;
    }

    ret = kstrtol(token, 10, &value);
    if (ret) {
      return ret;
    }

    if (value < 0 || value > PID_MAX_LIMIT) {
      return -ERANGE;
    }

    for (i = 0; i < idx; ++i) {
      if (out[i] == (pid_t)value) {
        exists = true;
        break;
      }
    }

    if (exists) {
      continue;
    }

    if (idx >= max) {
      return -E2BIG;
    }

    out[idx++] = (pid_t)value;
  }

  *count = idx;
  return 0;
}

static struct proc_whitelist_node *proc_whitelist_lookup_locked(pid_t pid) {
  struct rb_node *node = g_proc_whitelist_index.rb_node;

  while (node) {
    struct proc_whitelist_node *entry =
        rb_entry(node, struct proc_whitelist_node, rb);
    if (pid < entry->pid) {
      node = node->rb_left;
    } else if (pid > entry->pid) {
      node = node->rb_right;
    } else {
      return entry;
    }
  }

  return NULL;
}

static int proc_whitelist_insert_node_locked(struct proc_whitelist_node *node) {
  struct rb_node **link = &g_proc_whitelist_index.rb_node;
  struct rb_node *parent = NULL;

  while (*link) {
    struct proc_whitelist_node *entry =
        rb_entry(*link, struct proc_whitelist_node, rb);
    parent = *link;
    if (node->pid < entry->pid) {
      link = &(*link)->rb_left;
    } else if (node->pid > entry->pid) {
      link = &(*link)->rb_right;
    } else {
      return -EEXIST;
    }
  }

  rb_link_node(&node->rb, parent, link);
  rb_insert_color(&node->rb, &g_proc_whitelist_index);
  return 0;
}

static struct proc_whitelist_node *proc_whitelist_create_node(pid_t pid) {
  struct proc_whitelist_node *node;

  node = kzalloc(sizeof(*node), GFP_KERNEL);
  if (!node) {
    return NULL;
  }

  node->pid = pid;
  node->is_explicit = false;
  node->include_children = true;
  node->parent = NULL;
  INIT_LIST_HEAD(&node->sibling);
  INIT_LIST_HEAD(&node->children);

  return node;
}

static void
proc_whitelist_attach_node_locked(struct proc_whitelist_node *node,
                                  struct proc_whitelist_node *parent) {
  if (!node) {
    return;
  }

  list_del_init(&node->sibling);
  node->parent = parent;
  if (parent) {
    list_add_tail(&node->sibling, &parent->children);
  } else {
    list_add_tail(&node->sibling, &g_proc_whitelist_roots);
  }
}

static void
proc_whitelist_free_node_recursive(struct proc_whitelist_node *node) {
  struct proc_whitelist_node *child, *tmp;

  if (!node) {
    return;
  }

  list_for_each_entry_safe(child, tmp, &node->children, sibling) {
    proc_whitelist_free_node_recursive(child);
  }

  rb_erase(&node->rb, &g_proc_whitelist_index);
  list_del_init(&node->sibling);
  INIT_LIST_HEAD(&node->children);
  kfree(node);
}

static void proc_whitelist_clear_locked(void) {
  struct proc_whitelist_node *node, *tmp;

  list_for_each_entry_safe(node, tmp, &g_proc_whitelist_roots, sibling) {
    proc_whitelist_free_node_recursive(node);
  }

  g_proc_whitelist_explicit_count = 0;
  g_proc_whitelist_node_count = 0;
  g_proc_whitelist_raw[0] = '\0';
}

static void proc_whitelist_prune_locked(struct proc_whitelist_node *node) {
  struct proc_whitelist_node *parent;

  while (node && !node->is_explicit && list_empty(&node->children)) {
    parent = node->parent;
    rb_erase(&node->rb, &g_proc_whitelist_index);
    list_del_init(&node->sibling);
    kfree(node);
    if (g_proc_whitelist_node_count > 0) {
      g_proc_whitelist_node_count--;
    }
    node = parent;
  }
}

static int proc_whitelist_append(char *buffer, size_t buflen, size_t *offset,
                                 const char *fmt, ...) {
  va_list args;
  int written;

  if (!buffer || !offset || *offset >= buflen) {
    return -ENOSPC;
  }

  va_start(args, fmt);
  written = vscnprintf(buffer + *offset, buflen - *offset, fmt, args);
  va_end(args);

  if (written < 0) {
    return written;
  }

  *offset += written;
  return 0;
}

static int proc_whitelist_format_node(struct proc_whitelist_node *node,
                                      char *buffer, size_t buflen,
                                      size_t *offset, bool first) {
  struct proc_whitelist_node *child;
  bool first_child = true;
  int ret;

  if (!node) {
    return 0;
  }

  if (!first) {
    ret = proc_whitelist_append(buffer, buflen, offset, ", ");
    if (ret) {
      return ret;
    }
  }

  ret = proc_whitelist_append(buffer, buflen, offset, "%d%s%s", node->pid,
                              node->include_children ? "*" : "!",
                              node->is_explicit ? "" : "?");
  if (ret) {
    return ret;
  }

  if (!list_empty(&node->children)) {
    ret = proc_whitelist_append(buffer, buflen, offset, " (");
    if (ret) {
      return ret;
    }

    list_for_each_entry(child, &node->children, sibling) {
      ret = proc_whitelist_format_node(child, buffer, buflen, offset,
                                       first_child);
      if (ret) {
        return ret;
      }
      first_child = false;
    }

    ret = proc_whitelist_append(buffer, buflen, offset, ")");
    if (ret) {
      return ret;
    }
  }

  return 0;
}

static void proc_whitelist_refresh_string_locked(void) {
  struct proc_whitelist_node *node;
  size_t offset = 0;
  bool first = true;
  int ret;

  g_proc_whitelist_raw[0] = '\0';

  list_for_each_entry(node, &g_proc_whitelist_roots, sibling) {
    ret = proc_whitelist_format_node(node, g_proc_whitelist_raw,
                                     sizeof(g_proc_whitelist_raw), &offset,
                                     first);
    if (ret) {
      strscpy(g_proc_whitelist_raw, "<truncated>",
              sizeof(g_proc_whitelist_raw));
      return;
    }
    first = false;
  }
}

static bool proc_whitelist_node_allows(struct proc_whitelist_node *node) {
  bool is_self = true;

  while (node) {
    if (node->is_explicit) {
      if (is_self) {
        return true;
      }
      if (node->include_children) {
        return true;
      }
    }
    node = node->parent;
    is_self = false;
  }

  return false;
}

static int proc_whitelist_collect_lineage(pid_t pid, pid_t *lineage,
                                          size_t *depth) {
  struct task_struct *task;
  size_t count = 0;

  if (!lineage || !depth) {
    return -EINVAL;
  }

  rcu_read_lock();
  task = pid_task(find_vpid(pid), PIDTYPE_PID);
  if (!task) {
    rcu_read_unlock();
    return -ESRCH;
  }

  while (task && count < PROC_WHITELIST_LINEAGE_MAX) {
    lineage[count++] = task_pid_nr(task);
    if (task->pid == 0 || task == task->real_parent) {
      break;
    }
    task = rcu_dereference(task->real_parent);
  }
  rcu_read_unlock();

  if (count >= PROC_WHITELIST_LINEAGE_MAX && lineage[count - 1] != 0 &&
      lineage[count - 1] != 1) {
    return -E2BIG;
  }

  *depth = count;
  return 0;
}

static int proc_whitelist_upsert_chain_locked(const pid_t *lineage,
                                              size_t depth,
                                              bool include_children) {
  struct proc_whitelist_node *parent = NULL;
  struct proc_whitelist_node *node = NULL;
  size_t idx;
  int ret;

  if (!lineage || depth == 0) {
    return -EINVAL;
  }

  node = proc_whitelist_lookup_locked(lineage[0]);
  if ((!node || !node->is_explicit) &&
      g_proc_whitelist_explicit_count >= PROC_WHITELIST_MAX_EXPLICIT) {
    return -E2BIG;
  }

  for (idx = depth; idx-- > 0;) {
    pid_t current_pid = lineage[idx];
    node = proc_whitelist_lookup_locked(current_pid);
    if (!node) {
      node = proc_whitelist_create_node(current_pid);
      if (!node) {
        return -ENOMEM;
      }
      ret = proc_whitelist_insert_node_locked(node);
      if (ret) {
        kfree(node);
        return ret;
      }
      proc_whitelist_attach_node_locked(node, parent);
      g_proc_whitelist_node_count++;
    } else if (node->parent != parent) {
      proc_whitelist_attach_node_locked(node, parent);
    }
    parent = node;
  }

  if (!node) {
    return -EINVAL;
  }

  if (!node->is_explicit) {
    if (g_proc_whitelist_explicit_count >= PROC_WHITELIST_MAX_EXPLICIT) {
      return -E2BIG;
    }
    node->is_explicit = true;
    g_proc_whitelist_explicit_count++;
  }
  node->include_children = include_children;

  return 0;
}

static void proc_whitelist_skip_spaces(const char **cursor) {
  if (!cursor || !*cursor) {
    return;
  }

  while (**cursor && isspace(**cursor)) {
    (*cursor)++;
  }
}

static int proc_whitelist_parse_number(const char **cursor, pid_t *pid) {
  long value;
  char *end;

  if (!cursor || !*cursor || !pid) {
    return -EINVAL;
  }

  proc_whitelist_skip_spaces(cursor);

  if (!isdigit(**cursor)) {
    return -EINVAL;
  }

  value = simple_strtol(*cursor, &end, 10);
  if (value <= 0 || value > PID_MAX_LIMIT) {
    return -ERANGE;
  }

  *pid = (pid_t)value;
  *cursor = end;
  return 0;
}

static struct proc_whitelist_parsed_node *
proc_whitelist_alloc_parsed_node(pid_t pid, bool include_children,
                                 bool is_explicit) {
  struct proc_whitelist_parsed_node *node;

  node = kzalloc(sizeof(*node), GFP_KERNEL);
  if (!node) {
    return NULL;
  }

  node->pid = pid;
  node->include_children = include_children;
  node->is_explicit = is_explicit;
  INIT_LIST_HEAD(&node->sibling);
  INIT_LIST_HEAD(&node->children);

  return node;
}

static void
proc_whitelist_free_parsed_node(struct proc_whitelist_parsed_node *node) {
  struct proc_whitelist_parsed_node *child, *tmp;

  if (!node) {
    return;
  }

  list_for_each_entry_safe(child, tmp, &node->children, sibling) {
    proc_whitelist_free_parsed_node(child);
  }
  kfree(node);
}

static void proc_whitelist_free_parsed_tree(struct list_head *roots) {
  struct proc_whitelist_parsed_node *node, *tmp;

  if (!roots) {
    return;
  }

  list_for_each_entry_safe(node, tmp, roots, sibling) {
    list_del_init(&node->sibling);
    proc_whitelist_free_parsed_node(node);
  }
  INIT_LIST_HEAD(roots);
}

static int proc_whitelist_parse_node(const char **cursor, size_t depth,
                                     struct proc_whitelist_parsed_node **out,
                                     size_t *explicit_count) {
  struct proc_whitelist_parsed_node *node = NULL;
  bool include_children = true;
  bool is_explicit = true;
  pid_t pid;
  int ret;

  if (!cursor || !*cursor || !out) {
    return -EINVAL;
  }

  if (depth >= PROC_WHITELIST_LINEAGE_MAX) {
    return -E2BIG;
  }

  ret = proc_whitelist_parse_number(cursor, &pid);
  if (ret) {
    return ret;
  }

  proc_whitelist_skip_spaces(cursor);
  if (**cursor == '*' || **cursor == '!') {
    include_children = (**cursor == '*');
    (*cursor)++;
  }

  proc_whitelist_skip_spaces(cursor);
  if (**cursor == '?') {
    is_explicit = false;
    (*cursor)++;
  }

  node = proc_whitelist_alloc_parsed_node(pid, include_children, is_explicit);
  if (!node) {
    return -ENOMEM;
  }

  if (is_explicit && explicit_count) {
    (*explicit_count)++;
  }

  proc_whitelist_skip_spaces(cursor);
  if (**cursor == '(') {
    (*cursor)++;
    while (true) {
      struct proc_whitelist_parsed_node *child;

      proc_whitelist_skip_spaces(cursor);
      if (**cursor == ')') {
        break;
      }

      ret =
          proc_whitelist_parse_node(cursor, depth + 1, &child, explicit_count);
      if (ret) {
        proc_whitelist_free_parsed_node(node);
        return ret;
      }
      list_add_tail(&child->sibling, &node->children);

      proc_whitelist_skip_spaces(cursor);
      if (**cursor == ',') {
        (*cursor)++;
        continue;
      }
      break;
    }

    proc_whitelist_skip_spaces(cursor);
    if (**cursor != ')') {
      proc_whitelist_free_parsed_node(node);
      return -EINVAL;
    }
    (*cursor)++;
  }

  *out = node;
  return 0;
}

static int proc_whitelist_parse_tree(const char *input, struct list_head *roots,
                                     size_t *explicit_count) {
  const char *cursor = input;
  int ret = 0;

  if (!roots) {
    return -EINVAL;
  }

  INIT_LIST_HEAD(roots);
  if (explicit_count) {
    *explicit_count = 0;
  }

  proc_whitelist_skip_spaces(&cursor);
  if (!*cursor) {
    return 0;
  }

  while (*cursor) {
    struct proc_whitelist_parsed_node *node;
    ret = proc_whitelist_parse_node(&cursor, 0, &node, explicit_count);
    if (ret) {
      proc_whitelist_free_parsed_tree(roots);
      return ret;
    }
    list_add_tail(&node->sibling, roots);

    proc_whitelist_skip_spaces(&cursor);
    if (*cursor == ',') {
      cursor++;
      continue;
    }
    break;
  }

  proc_whitelist_skip_spaces(&cursor);
  if (*cursor != '\0') {
    proc_whitelist_free_parsed_tree(roots);
    return -EINVAL;
  }

  return 0;
}

static int proc_whitelist_apply_parsed_node_locked(
    struct proc_whitelist_parsed_node *parsed,
    struct proc_whitelist_node *parent) {
  struct proc_whitelist_node *node;
  struct proc_whitelist_parsed_node *child;
  int ret;

  node = proc_whitelist_create_node(parsed->pid);
  if (!node) {
    return -ENOMEM;
  }

  node->is_explicit = parsed->is_explicit;
  node->include_children = parsed->include_children;

  ret = proc_whitelist_insert_node_locked(node);
  if (ret) {
    kfree(node);
    return ret;
  }
  proc_whitelist_attach_node_locked(node, parent);
  g_proc_whitelist_node_count++;
  if (node->is_explicit) {
    g_proc_whitelist_explicit_count++;
  }

  list_for_each_entry(child, &parsed->children, sibling) {
    ret = proc_whitelist_apply_parsed_node_locked(child, node);
    if (ret) {
      return ret;
    }
  }

  return 0;
}

static int proc_whitelist_apply_parsed_roots_locked(struct list_head *roots) {
  struct proc_whitelist_parsed_node *node;
  int ret;

  list_for_each_entry(node, roots, sibling) {
    ret = proc_whitelist_apply_parsed_node_locked(node, NULL);
    if (ret) {
      return ret;
    }
  }

  return 0;
}

int proc_whitelist_add(pid_t pid, bool include_children) {
  pid_t lineage[PROC_WHITELIST_LINEAGE_MAX];
  size_t depth = 0;
  int ret;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return -EINVAL;
  }

  ret = proc_whitelist_collect_lineage(pid, lineage, &depth);
  if (ret) {
    return ret;
  }

  write_lock(&g_rwlock);
  ret = proc_whitelist_upsert_chain_locked(lineage, depth, include_children);
  if (!ret) {
    proc_whitelist_refresh_string_locked();
    pr_info("proc_whitelist: added pid=%d inherit_children=%d (count=%zu)\n",
            pid, include_children, g_proc_whitelist_explicit_count);
  }
  write_unlock(&g_rwlock);

  return ret;
}

int proc_whitelist_remove(pid_t pid, bool include_children) {
  struct proc_whitelist_node *node;
  int ret = 0;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return -EINVAL;
  }

  write_lock(&g_rwlock);
  node = proc_whitelist_lookup_locked(pid);
  if (!node || !node->is_explicit) {
    ret = -ENOENT;
    goto out_unlock;
  }

  if (node->include_children != include_children) {
    ret = -EINVAL;
    goto out_unlock;
  }

  node->is_explicit = false;
  if (g_proc_whitelist_explicit_count > 0) {
    g_proc_whitelist_explicit_count--;
  }
  proc_whitelist_prune_locked(node);
  proc_whitelist_refresh_string_locked();
  pr_info("proc_whitelist: removed pid=%d inherit_children=%d (count=%zu)\n",
          pid, include_children, g_proc_whitelist_explicit_count);

out_unlock:
  write_unlock(&g_rwlock);
  return ret;
}

bool proc_whitelist_contains(pid_t pid) {
  struct proc_whitelist_node *node;
  pid_t lineage[PROC_WHITELIST_LINEAGE_MAX];
  size_t depth = 0;
  bool allowed = false;
  int ret;
  size_t i;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return false;
  }

  read_lock(&g_rwlock);
  node = proc_whitelist_lookup_locked(pid);
  if (node) {
    allowed = proc_whitelist_node_allows(node);
  }
  read_unlock(&g_rwlock);

  if (allowed) {
    return true;
  }

  ret = proc_whitelist_collect_lineage(pid, lineage, &depth);
  if (ret) {
    return false;
  }

  read_lock(&g_rwlock);
  for (i = 0; i < depth; ++i) {
    struct proc_whitelist_node *ancestor =
        proc_whitelist_lookup_locked(lineage[i]);
    if (!ancestor || !ancestor->is_explicit) {
      continue;
    }
    if (i == 0 || ancestor->include_children) {
      allowed = true;
      break;
    }
  }
  read_unlock(&g_rwlock);

  return allowed;
}

static int proc_whitelist_apply_flat_list(const pid_t *pids, size_t count) {
  struct proc_whitelist_lineage_cache {
    pid_t lineage[PROC_WHITELIST_LINEAGE_MAX];
    size_t depth;
  };
  struct proc_whitelist_lineage_cache *cache;
  size_t i;
  int ret = 0;

  if (count > PROC_WHITELIST_MAX_EXPLICIT) {
    return -E2BIG;
  }

  if (count == 0) {
    write_lock(&g_rwlock);
    proc_whitelist_clear_locked();
    proc_whitelist_refresh_string_locked();
    write_unlock(&g_rwlock);
    return 0;
  }

  cache = kcalloc(count, sizeof(*cache), GFP_KERNEL);
  if (!cache) {
    return -ENOMEM;
  }

  for (i = 0; i < count; ++i) {
    ret = proc_whitelist_collect_lineage(pids[i], cache[i].lineage,
                                         &cache[i].depth);
    if (ret) {
      kfree(cache);
      return ret;
    }
  }

  write_lock(&g_rwlock);
  proc_whitelist_clear_locked();
  for (i = 0; i < count; ++i) {
    ret = proc_whitelist_upsert_chain_locked(cache[i].lineage, cache[i].depth,
                                             true);
    if (ret) {
      proc_whitelist_clear_locked();
      break;
    }
  }
  if (!ret) {
    proc_whitelist_refresh_string_locked();
  }
  write_unlock(&g_rwlock);

  kfree(cache);
  return ret;
}

static int proc_whitelist_apply_tree_string(char *input) {
  LIST_HEAD(parsed_roots);
  size_t explicit_count = 0;
  size_t final_count = 0;
  int ret;

  ret = proc_whitelist_parse_tree(input, &parsed_roots, &explicit_count);
  if (ret) {
    proc_whitelist_free_parsed_tree(&parsed_roots);
    return ret;
  }

  if (explicit_count > PROC_WHITELIST_MAX_EXPLICIT) {
    proc_whitelist_free_parsed_tree(&parsed_roots);
    return -E2BIG;
  }

  write_lock(&g_rwlock);
  proc_whitelist_clear_locked();
  ret = proc_whitelist_apply_parsed_roots_locked(&parsed_roots);
  if (ret) {
    proc_whitelist_clear_locked();
  } else {
    proc_whitelist_refresh_string_locked();
    final_count = g_proc_whitelist_explicit_count;
  }
  write_unlock(&g_rwlock);

  proc_whitelist_free_parsed_tree(&parsed_roots);
  if (!ret) {
    pr_info("proc_whitelist: updated (%zu entries)\n", final_count);
  }
  return ret;
}

static int proc_whitelist_param_set(const char *val,
                                    const struct kernel_param *kp) {
  char *buf = NULL;
  char *trimmed;
  pid_t *parsed = NULL;
  size_t count = 0;
  bool use_tree_format;
  int ret;

  if (!val) {
    return -EINVAL;
  }

  buf = kcalloc(PROC_WHITELIST_PARAM_LEN, sizeof(char), GFP_KERNEL);
  if (!buf) {
    return -ENOMEM;
  }

  strscpy(buf, val, PROC_WHITELIST_PARAM_LEN);
  trimmed = strim(buf);
  if (!trimmed || !*trimmed) {
    write_lock(&g_rwlock);
    proc_whitelist_clear_locked();
    proc_whitelist_refresh_string_locked();
    write_unlock(&g_rwlock);
    pr_info("proc_whitelist: cleared\n");
    kfree(buf);
    return 0;
  }

  use_tree_format = strpbrk(trimmed, "()!?*") != NULL;
  if (use_tree_format) {
    ret = proc_whitelist_apply_tree_string(trimmed);
    kfree(buf);
    return ret;
  }

  parsed = kcalloc(PROC_WHITELIST_MAX_EXPLICIT, sizeof(*parsed), GFP_KERNEL);
  if (!parsed) {
    kfree(buf);
    return -ENOMEM;
  }

  ret = parse_proc_list(trimmed, parsed, PROC_WHITELIST_MAX_EXPLICIT, &count);
  kfree(buf);
  if (ret) {
    kfree(parsed);
    return ret;
  }

  ret = proc_whitelist_apply_flat_list(parsed, count);
  kfree(parsed);
  if (!ret) {
    pr_info("proc_whitelist: updated (%zu entries)\n", count);
  }
  return ret;
}

static int proc_whitelist_param_get(char *buffer,
                                    const struct kernel_param *kp) {
  int len;

  if (!buffer) {
    return -EINVAL;
  }

  read_lock(&g_rwlock);
  if (g_proc_whitelist_raw[0] == '\0') {
    len = scnprintf(buffer, PAGE_SIZE, "\n");
  } else {
    len = scnprintf(buffer, PAGE_SIZE, "%s\n", g_proc_whitelist_raw);
  }
  read_unlock(&g_rwlock);

  return len;
}

static const struct kernel_param_ops proc_whitelist_ops = {
    .set = proc_whitelist_param_set,
    .get = proc_whitelist_param_get,
};

module_param_cb(proc_whitelist, &proc_whitelist_ops, NULL, 0644);
MODULE_PARM_DESC(proc_whitelist,
                 "Tree-shaped process whitelist (pid[*|!][?] (children...))");
