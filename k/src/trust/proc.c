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

#include "tcm/trust/proc.h"

/*
 * PROC 白名单：
 *  - 使用树结构模拟当前（添加时观察到的）进程树
 *  - 支持标记是否对子进程生效，默认继承
 *  - module_param 提供树形字符串表示，兼容旧的逗号列表
 */

#define TRUST_PROC_MAX_EXPLICIT 128
#define TRUST_PROC_PARAM_LEN 4096
#define TRUST_PROC_LINEAGE_MAX 64

struct trust_proc_node {
  pid_t pid;
  bool is_explicit;
  bool include_children;
  struct trust_proc_node *parent;
  struct rb_node rb;
  struct list_head sibling;
  struct list_head children;
};

struct trust_proc_parsed_node {
  pid_t pid;
  bool include_children;
  bool is_explicit;
  struct list_head sibling;
  struct list_head children;
};

static DEFINE_RWLOCK(g_rwlock);
static struct rb_root g_trust_proc_index = RB_ROOT;
static LIST_HEAD(g_trust_proc_roots);
static size_t g_trust_proc_explicit_count;
static size_t g_trust_proc_node_count;
static char g_trust_proc_raw[TRUST_PROC_PARAM_LEN];

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

static struct trust_proc_node *trust_proc_lookup_locked(pid_t pid) {
  struct rb_node *node = g_trust_proc_index.rb_node;

  while (node) {
    struct trust_proc_node *entry = rb_entry(node, struct trust_proc_node, rb);
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

static int trust_proc_insert_node_locked(struct trust_proc_node *node) {
  struct rb_node **link = &g_trust_proc_index.rb_node;
  struct rb_node *parent = NULL;

  while (*link) {
    struct trust_proc_node *entry = rb_entry(*link, struct trust_proc_node, rb);
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
  rb_insert_color(&node->rb, &g_trust_proc_index);
  return 0;
}

static struct trust_proc_node *trust_proc_create_node(pid_t pid) {
  struct trust_proc_node *node;

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

static void trust_proc_attach_node_locked(struct trust_proc_node *node,
                                          struct trust_proc_node *parent) {
  if (!node) {
    return;
  }

  list_del_init(&node->sibling);
  node->parent = parent;
  if (parent) {
    list_add_tail(&node->sibling, &parent->children);
  } else {
    list_add_tail(&node->sibling, &g_trust_proc_roots);
  }
}

static void trust_proc_free_node_recursive(struct trust_proc_node *node) {
  struct trust_proc_node *child, *tmp;

  if (!node) {
    return;
  }

  list_for_each_entry_safe(child, tmp, &node->children, sibling) {
    trust_proc_free_node_recursive(child);
  }

  rb_erase(&node->rb, &g_trust_proc_index);
  list_del_init(&node->sibling);
  INIT_LIST_HEAD(&node->children);
  kfree(node);
}

static void trust_proc_clear_locked(void) {
  struct trust_proc_node *node, *tmp;

  list_for_each_entry_safe(node, tmp, &g_trust_proc_roots, sibling) {
    trust_proc_free_node_recursive(node);
  }

  g_trust_proc_explicit_count = 0;
  g_trust_proc_node_count = 0;
  g_trust_proc_raw[0] = '\0';
}

static void trust_proc_prune_locked(struct trust_proc_node *node) {
  struct trust_proc_node *parent;

  while (node && !node->is_explicit && list_empty(&node->children)) {
    parent = node->parent;
    rb_erase(&node->rb, &g_trust_proc_index);
    list_del_init(&node->sibling);
    kfree(node);
    if (g_trust_proc_node_count > 0) {
      g_trust_proc_node_count--;
    }
    node = parent;
  }
}

static int trust_proc_append(char *buffer, size_t buflen, size_t *offset,
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

static int trust_proc_format_node(struct trust_proc_node *node, char *buffer,
                                  size_t buflen, size_t *offset, bool first) {
  struct trust_proc_node *child;
  bool first_child = true;
  int ret;

  if (!node) {
    return 0;
  }

  if (!first) {
    ret = trust_proc_append(buffer, buflen, offset, ", ");
    if (ret) {
      return ret;
    }
  }

  ret = trust_proc_append(buffer, buflen, offset, "%d%s%s", node->pid,
                          node->include_children ? "*" : "!",
                          node->is_explicit ? "" : "?");
  if (ret) {
    return ret;
  }

  if (!list_empty(&node->children)) {
    ret = trust_proc_append(buffer, buflen, offset, " (");
    if (ret) {
      return ret;
    }

    list_for_each_entry(child, &node->children, sibling) {
      ret = trust_proc_format_node(child, buffer, buflen, offset, first_child);
      if (ret) {
        return ret;
      }
      first_child = false;
    }

    ret = trust_proc_append(buffer, buflen, offset, ")");
    if (ret) {
      return ret;
    }
  }

  return 0;
}

static void trust_proc_refresh_string_locked(void) {
  struct trust_proc_node *node;
  size_t offset = 0;
  bool first = true;
  int ret;

  g_trust_proc_raw[0] = '\0';

  list_for_each_entry(node, &g_trust_proc_roots, sibling) {
    ret = trust_proc_format_node(node, g_trust_proc_raw,
                                 sizeof(g_trust_proc_raw), &offset, first);
    if (ret) {
      strscpy(g_trust_proc_raw, "<truncated>", sizeof(g_trust_proc_raw));
      return;
    }
    first = false;
  }
}

static bool trust_proc_node_allows(struct trust_proc_node *node) {
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

static int trust_proc_collect_lineage(pid_t pid, pid_t *lineage,
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

  while (task && count < TRUST_PROC_LINEAGE_MAX) {
    lineage[count++] = task_pid_nr(task);
    if (task->pid == 0 || task == task->real_parent) {
      break;
    }
    task = rcu_dereference(task->real_parent);
  }
  rcu_read_unlock();

  if (count >= TRUST_PROC_LINEAGE_MAX && lineage[count - 1] != 0 &&
      lineage[count - 1] != 1) {
    return -E2BIG;
  }

  *depth = count;
  return 0;
}

static int trust_proc_upsert_chain_locked(const pid_t *lineage, size_t depth,
                                          bool include_children) {
  struct trust_proc_node *parent = NULL;
  struct trust_proc_node *node = NULL;
  size_t idx;
  int ret;

  if (!lineage || depth == 0) {
    return -EINVAL;
  }

  node = trust_proc_lookup_locked(lineage[0]);
  if ((!node || !node->is_explicit) &&
      g_trust_proc_explicit_count >= TRUST_PROC_MAX_EXPLICIT) {
    return -E2BIG;
  }

  for (idx = depth; idx-- > 0;) {
    pid_t current_pid = lineage[idx];
    node = trust_proc_lookup_locked(current_pid);
    if (!node) {
      node = trust_proc_create_node(current_pid);
      if (!node) {
        return -ENOMEM;
      }
      ret = trust_proc_insert_node_locked(node);
      if (ret) {
        kfree(node);
        return ret;
      }
      trust_proc_attach_node_locked(node, parent);
      g_trust_proc_node_count++;
    } else if (node->parent != parent) {
      trust_proc_attach_node_locked(node, parent);
    }
    parent = node;
  }

  if (!node) {
    return -EINVAL;
  }

  if (!node->is_explicit) {
    if (g_trust_proc_explicit_count >= TRUST_PROC_MAX_EXPLICIT) {
      return -E2BIG;
    }
    node->is_explicit = true;
    g_trust_proc_explicit_count++;
  }
  node->include_children = include_children;

  return 0;
}

static void trust_proc_skip_spaces(const char **cursor) {
  if (!cursor || !*cursor) {
    return;
  }

  while (**cursor && isspace(**cursor)) {
    (*cursor)++;
  }
}

static int trust_proc_parse_number(const char **cursor, pid_t *pid) {
  long value;
  char *end;

  if (!cursor || !*cursor || !pid) {
    return -EINVAL;
  }

  trust_proc_skip_spaces(cursor);

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

static struct trust_proc_parsed_node *
trust_proc_alloc_parsed_node(pid_t pid, bool include_children,
                             bool is_explicit) {
  struct trust_proc_parsed_node *node;

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

static void trust_proc_free_parsed_node(struct trust_proc_parsed_node *node) {
  struct trust_proc_parsed_node *child, *tmp;

  if (!node) {
    return;
  }

  list_for_each_entry_safe(child, tmp, &node->children, sibling) {
    trust_proc_free_parsed_node(child);
  }
  kfree(node);
}

static void trust_proc_free_parsed_tree(struct list_head *roots) {
  struct trust_proc_parsed_node *node, *tmp;

  if (!roots) {
    return;
  }

  list_for_each_entry_safe(node, tmp, roots, sibling) {
    list_del_init(&node->sibling);
    trust_proc_free_parsed_node(node);
  }
  INIT_LIST_HEAD(roots);
}

static int trust_proc_parse_node(const char **cursor, size_t depth,
                                 struct trust_proc_parsed_node **out,
                                 size_t *explicit_count) {
  struct trust_proc_parsed_node *node = NULL;
  bool include_children = true;
  bool is_explicit = true;
  pid_t pid;
  int ret;

  if (!cursor || !*cursor || !out) {
    return -EINVAL;
  }

  if (depth >= TRUST_PROC_LINEAGE_MAX) {
    return -E2BIG;
  }

  ret = trust_proc_parse_number(cursor, &pid);
  if (ret) {
    return ret;
  }

  trust_proc_skip_spaces(cursor);
  if (**cursor == '*' || **cursor == '!') {
    include_children = (**cursor == '*');
    (*cursor)++;
  }

  trust_proc_skip_spaces(cursor);
  if (**cursor == '?') {
    is_explicit = false;
    (*cursor)++;
  }

  node = trust_proc_alloc_parsed_node(pid, include_children, is_explicit);
  if (!node) {
    return -ENOMEM;
  }

  if (is_explicit && explicit_count) {
    (*explicit_count)++;
  }

  trust_proc_skip_spaces(cursor);
  if (**cursor == '(') {
    (*cursor)++;
    while (true) {
      struct trust_proc_parsed_node *child;

      trust_proc_skip_spaces(cursor);
      if (**cursor == ')') {
        break;
      }

      ret = trust_proc_parse_node(cursor, depth + 1, &child, explicit_count);
      if (ret) {
        trust_proc_free_parsed_node(node);
        return ret;
      }
      list_add_tail(&child->sibling, &node->children);

      trust_proc_skip_spaces(cursor);
      if (**cursor == ',') {
        (*cursor)++;
        continue;
      }
      break;
    }

    trust_proc_skip_spaces(cursor);
    if (**cursor != ')') {
      trust_proc_free_parsed_node(node);
      return -EINVAL;
    }
    (*cursor)++;
  }

  *out = node;
  return 0;
}

static int trust_proc_parse_tree(const char *input, struct list_head *roots,
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

  trust_proc_skip_spaces(&cursor);
  if (!*cursor) {
    return 0;
  }

  while (*cursor) {
    struct trust_proc_parsed_node *node;
    ret = trust_proc_parse_node(&cursor, 0, &node, explicit_count);
    if (ret) {
      trust_proc_free_parsed_tree(roots);
      return ret;
    }
    list_add_tail(&node->sibling, roots);

    trust_proc_skip_spaces(&cursor);
    if (*cursor == ',') {
      cursor++;
      continue;
    }
    break;
  }

  trust_proc_skip_spaces(&cursor);
  if (*cursor != '\0') {
    trust_proc_free_parsed_tree(roots);
    return -EINVAL;
  }

  return 0;
}

static int
trust_proc_apply_parsed_node_locked(struct trust_proc_parsed_node *parsed,
                                    struct trust_proc_node *parent) {
  struct trust_proc_node *node;
  struct trust_proc_parsed_node *child;
  int ret;

  node = trust_proc_create_node(parsed->pid);
  if (!node) {
    return -ENOMEM;
  }

  node->is_explicit = parsed->is_explicit;
  node->include_children = parsed->include_children;

  ret = trust_proc_insert_node_locked(node);
  if (ret) {
    kfree(node);
    return ret;
  }
  trust_proc_attach_node_locked(node, parent);
  g_trust_proc_node_count++;
  if (node->is_explicit) {
    g_trust_proc_explicit_count++;
  }

  list_for_each_entry(child, &parsed->children, sibling) {
    ret = trust_proc_apply_parsed_node_locked(child, node);
    if (ret) {
      return ret;
    }
  }

  return 0;
}

static int trust_proc_apply_parsed_roots_locked(struct list_head *roots) {
  struct trust_proc_parsed_node *node;
  int ret;

  list_for_each_entry(node, roots, sibling) {
    ret = trust_proc_apply_parsed_node_locked(node, NULL);
    if (ret) {
      return ret;
    }
  }

  return 0;
}

int trust_proc_add(pid_t pid, bool include_children) {
  pid_t lineage[TRUST_PROC_LINEAGE_MAX];
  size_t depth = 0;
  int ret;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return -EINVAL;
  }

  ret = trust_proc_collect_lineage(pid, lineage, &depth);
  if (ret) {
    return ret;
  }

  write_lock(&g_rwlock);
  ret = trust_proc_upsert_chain_locked(lineage, depth, include_children);
  if (!ret) {
    trust_proc_refresh_string_locked();
    pr_info("trust_proc: added pid=%d inherit_children=%d (count=%zu)\n", pid,
            include_children, g_trust_proc_explicit_count);
  }
  write_unlock(&g_rwlock);

  return ret;
}

int trust_proc_remove(pid_t pid, bool include_children) {
  struct trust_proc_node *node;
  int ret = 0;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return -EINVAL;
  }

  write_lock(&g_rwlock);
  node = trust_proc_lookup_locked(pid);
  if (!node || !node->is_explicit) {
    ret = -ENOENT;
    goto out_unlock;
  }

  if (node->include_children != include_children) {
    ret = -EINVAL;
    goto out_unlock;
  }

  node->is_explicit = false;
  if (g_trust_proc_explicit_count > 0) {
    g_trust_proc_explicit_count--;
  }
  trust_proc_prune_locked(node);
  trust_proc_refresh_string_locked();
  pr_info("trust_proc: removed pid=%d inherit_children=%d (count=%zu)\n", pid,
          include_children, g_trust_proc_explicit_count);

out_unlock:
  write_unlock(&g_rwlock);
  return ret;
}

bool trust_proc_contains(pid_t pid) {
  struct trust_proc_node *node;
  pid_t lineage[TRUST_PROC_LINEAGE_MAX];
  size_t depth = 0;
  bool allowed = false;
  int ret;
  size_t i;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return false;
  }

  read_lock(&g_rwlock);
  node = trust_proc_lookup_locked(pid);
  if (node) {
    allowed = trust_proc_node_allows(node);
  }
  read_unlock(&g_rwlock);

  if (allowed) {
    return true;
  }

  ret = trust_proc_collect_lineage(pid, lineage, &depth);
  if (ret) {
    return false;
  }

  read_lock(&g_rwlock);
  for (i = 0; i < depth; ++i) {
    struct trust_proc_node *ancestor = trust_proc_lookup_locked(lineage[i]);
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

static int trust_proc_apply_flat_list(const pid_t *pids, size_t count) {
  struct trust_proc_lineage_cache {
    pid_t lineage[TRUST_PROC_LINEAGE_MAX];
    size_t depth;
  };
  struct trust_proc_lineage_cache *cache;
  size_t i;
  int ret = 0;

  if (count > TRUST_PROC_MAX_EXPLICIT) {
    return -E2BIG;
  }

  if (count == 0) {
    write_lock(&g_rwlock);
    trust_proc_clear_locked();
    trust_proc_refresh_string_locked();
    write_unlock(&g_rwlock);
    return 0;
  }

  cache = kcalloc(count, sizeof(*cache), GFP_KERNEL);
  if (!cache) {
    return -ENOMEM;
  }

  for (i = 0; i < count; ++i) {
    ret =
        trust_proc_collect_lineage(pids[i], cache[i].lineage, &cache[i].depth);
    if (ret) {
      kfree(cache);
      return ret;
    }
  }

  write_lock(&g_rwlock);
  trust_proc_clear_locked();
  for (i = 0; i < count; ++i) {
    ret =
        trust_proc_upsert_chain_locked(cache[i].lineage, cache[i].depth, true);
    if (ret) {
      trust_proc_clear_locked();
      break;
    }
  }
  if (!ret) {
    trust_proc_refresh_string_locked();
  }
  write_unlock(&g_rwlock);

  kfree(cache);
  return ret;
}

static int trust_proc_apply_tree_string(char *input) {
  LIST_HEAD(parsed_roots);
  size_t explicit_count = 0;
  size_t final_count = 0;
  int ret;

  ret = trust_proc_parse_tree(input, &parsed_roots, &explicit_count);
  if (ret) {
    trust_proc_free_parsed_tree(&parsed_roots);
    return ret;
  }

  if (explicit_count > TRUST_PROC_MAX_EXPLICIT) {
    trust_proc_free_parsed_tree(&parsed_roots);
    return -E2BIG;
  }

  write_lock(&g_rwlock);
  trust_proc_clear_locked();
  ret = trust_proc_apply_parsed_roots_locked(&parsed_roots);
  if (ret) {
    trust_proc_clear_locked();
  } else {
    trust_proc_refresh_string_locked();
    final_count = g_trust_proc_explicit_count;
  }
  write_unlock(&g_rwlock);

  trust_proc_free_parsed_tree(&parsed_roots);
  if (!ret) {
    pr_info("trust_proc: updated (%zu entries)\n", final_count);
  }
  return ret;
}

static int trust_proc_param_set(const char *val,
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

  buf = kcalloc(TRUST_PROC_PARAM_LEN, sizeof(char), GFP_KERNEL);
  if (!buf) {
    return -ENOMEM;
  }

  strscpy(buf, val, TRUST_PROC_PARAM_LEN);
  trimmed = strim(buf);
  if (!trimmed || !*trimmed) {
    write_lock(&g_rwlock);
    trust_proc_clear_locked();
    trust_proc_refresh_string_locked();
    write_unlock(&g_rwlock);
    pr_info("trust_proc: cleared\n");
    kfree(buf);
    return 0;
  }

  use_tree_format = strpbrk(trimmed, "()!?*") != NULL;
  if (use_tree_format) {
    ret = trust_proc_apply_tree_string(trimmed);
    kfree(buf);
    return ret;
  }

  parsed = kcalloc(TRUST_PROC_MAX_EXPLICIT, sizeof(*parsed), GFP_KERNEL);
  if (!parsed) {
    kfree(buf);
    return -ENOMEM;
  }

  ret = parse_proc_list(trimmed, parsed, TRUST_PROC_MAX_EXPLICIT, &count);
  kfree(buf);
  if (ret) {
    kfree(parsed);
    return ret;
  }

  ret = trust_proc_apply_flat_list(parsed, count);
  kfree(parsed);
  if (!ret) {
    pr_info("trust_proc: updated (%zu entries)\n", count);
  }
  return ret;
}

static int trust_proc_param_get(char *buffer, const struct kernel_param *kp) {
  int len;

  if (!buffer) {
    return -EINVAL;
  }

  read_lock(&g_rwlock);
  if (g_trust_proc_raw[0] == '\0') {
    len = scnprintf(buffer, PAGE_SIZE, "\n");
  } else {
    len = scnprintf(buffer, PAGE_SIZE, "%s\n", g_trust_proc_raw);
  }
  read_unlock(&g_rwlock);

  return len;
}

static const struct kernel_param_ops trust_proc_ops = {
    .set = trust_proc_param_set,
    .get = trust_proc_param_get,
};

module_param_cb(trust_proc, &trust_proc_ops, NULL, 0644);
MODULE_PARM_DESC(trust_proc,
                 "Tree-shaped trust-process (pid[*|!][?] (children...))");
