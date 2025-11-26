#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
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
 *  - module_param 提供树形字符串表示
 */


struct trust_proc_node {
  pid_t pid;
  bool is_explicit;
  bool is_tree;
  struct trust_proc_node *parent;
  struct rb_node rb;
  struct list_head sibling;
  struct list_head children;
};

struct trust_proc_parsed_node {
  pid_t pid;
  bool is_tree;
  bool is_explicit;
  struct list_head sibling;
  struct list_head children;
};

static DEFINE_RWLOCK(g_rwlock);
static struct rb_root g_trust_proc_root = RB_ROOT;

/* 解析用户输入的 PID 列表，自动去重。 */
static int parse_proc_list(char *input, pid_t **out, size_t *count) {
  char *cursor;
  char *token;
  size_t idx = 0;
  size_t capacity = 0;
  pid_t *buffer = NULL;
  int ret = 0;

  if (!out || !count || !input) {
    return -EINVAL;
  }

  cursor = input;

  while ((token = strsep(&cursor, ", \t")) != NULL) {
    long value;
    bool exists = false;
    size_t i;

    if (*token == '\0') {
      continue;
    }

    ret = kstrtol(token, 10, &value);
    if (ret) {
      goto err_out;
    }

    if (value < 0 || value > PID_MAX_LIMIT) {
      ret = -ERANGE;
      goto err_out;
    }

    for (i = 0; i < idx; ++i) {
      if (buffer[i] == (pid_t)value) {
        exists = true;
        break;
      }
    }

    if (exists) {
      continue;
    }

    if (idx == capacity) {
      size_t new_capacity;
      pid_t *tmp;

      if (capacity == 0) {
        new_capacity = 16;
      } else if (capacity >= PID_MAX_LIMIT) {
        ret = -E2BIG;
        goto err_out;
      } else {
        new_capacity = min_t(size_t, capacity * 2, (size_t)PID_MAX_LIMIT);
      }

      tmp = krealloc_array(buffer, new_capacity, sizeof(pid_t), GFP_KERNEL);
      if (!tmp) {
        ret = -ENOMEM;
        goto err_out;
      }
      buffer = tmp;
      capacity = new_capacity;
    }

    buffer[idx++] = (pid_t)value;
  }

  *count = idx;
  *out = buffer;
  return 0;

err_out:
  kfree(buffer);
  *out = NULL;
  return ret;
}

static struct trust_proc_node *trust_proc_lookup_locked(pid_t pid) {
  struct rb_node *node = g_trust_proc_root.rb_node;

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
  struct rb_node **link = &g_trust_proc_root.rb_node;
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
  rb_insert_color(&node->rb, &g_trust_proc_root);
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
  node->is_tree = true;
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

  rb_erase(&node->rb, &g_trust_proc_root);
  list_del_init(&node->sibling);
  INIT_LIST_HEAD(&node->children);
  kfree(node);
}

static void trust_proc_clear_locked(void) {
  struct rb_node *rbnode;

  while ((rbnode = rb_first(&g_trust_proc_root)) != NULL) {
    struct trust_proc_node *node =
        rb_entry(rbnode, struct trust_proc_node, rb);
    trust_proc_free_node_recursive(node);
  }
}

/* 修剪白名单树。 */
static void trust_proc_prune_locked(struct trust_proc_node *node) {
  struct trust_proc_node *parent;

  while (node && !node->is_explicit && list_empty(&node->children)) {
    parent = node->parent;
    rb_erase(&node->rb, &g_trust_proc_root);
    list_del_init(&node->sibling);
    kfree(node);
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
                          node->is_tree ? "*" : "!",
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

/* 检查进程是否在白名单中。 */
static bool trust_proc_node_contains(struct trust_proc_node *node) {
  bool is_self = true;

  while (node) {
    if (node->is_explicit) {
      if (is_self) {
        return true;
      }
      if (node->is_tree) {
        return true;
      }
    }
    node = node->parent;
    is_self = false;
  }

  return false;
}

/* 统计 lineage 深度，避免在 RCU 临界区内分配内存。 */
static int trust_proc_measure_lineage_depth(pid_t pid, size_t *depth) {
  struct task_struct *task;
  size_t count = 0;

  if (!depth) {
    return -EINVAL;
  }

  rcu_read_lock();
  task = pid_task(find_vpid(pid), PIDTYPE_PID);
  if (!task) {
    rcu_read_unlock();
    return -ESRCH;
  }

  while (task) {
    count++;
    if (task->pid == 0 || task == task->real_parent) {
      break;
    }
    task = rcu_dereference(task->real_parent);
    if (count >= PID_MAX_LIMIT) {
      rcu_read_unlock();
      return -E2BIG;
    }
  }

  rcu_read_unlock();
  *depth = count;
  return 0;
}

/* 收集进程的 lineage，即从当前进程到根进程的路径。 */
static int trust_proc_collect_lineage(pid_t pid, pid_t **lineage,
                                      size_t *depth) {
  struct task_struct *task;
  pid_t *buffer = NULL;
  size_t capacity = 0;
  size_t count = 0;
  int ret;

  if (!lineage || !depth) {
    return -EINVAL;
  }

  *lineage = NULL;
  ret = trust_proc_measure_lineage_depth(pid, &capacity);
  if (ret) {
    return ret;
  }

  if (!capacity) {
    *lineage = NULL;
    *depth = 0;
    return -ESRCH;
  }

  buffer = kcalloc(capacity, sizeof(pid_t), GFP_KERNEL);
  if (!buffer) {
    return -ENOMEM;
  }

  rcu_read_lock();
  task = pid_task(find_vpid(pid), PIDTYPE_PID);
  if (!task) {
    rcu_read_unlock();
    kfree(buffer);
    *lineage = NULL;
    return -ESRCH;
  }

  while (task && count < capacity) {
    buffer[count++] = task_pid_nr(task);
    if (task->pid == 0 || task == task->real_parent) {
      break;
    }
    task = rcu_dereference(task->real_parent);
  }
  rcu_read_unlock();

  if (count == 0) {
    kfree(buffer);
    *lineage = NULL;
    return -ESRCH;
  }

  if (count < capacity) {
    pid_t *shrunk = krealloc_array(buffer, count, sizeof(pid_t), GFP_KERNEL);
    if (shrunk) {
      buffer = shrunk;
    }
  }

  *lineage = buffer;
  *depth = count;
  return 0;
}

/* 更新或插入进程链。 */
static int trust_proc_upsert_chain_locked(const pid_t *lineage, size_t depth,
                                          bool is_tree) {
  struct trust_proc_node *parent = NULL;
  struct trust_proc_node *node = NULL;
  size_t idx;
  int ret;

  if (!lineage || depth == 0) {
    return -EINVAL;
  }

  for (idx = depth; idx-- > 0;) {
    /* 从 lineage 的末尾(根进程)开始，逐个处理每个进程。 */
    pid_t current_pid = lineage[idx];
    node = trust_proc_lookup_locked(current_pid);
    if (!node) {
      /* 如果进程不存在，则创建新的节点。 */
      node = trust_proc_create_node(current_pid);
      if (!node) {
        return -ENOMEM;
      }
      /* 将新节点插入红黑树。 */
      ret = trust_proc_insert_node_locked(node);
      if (ret) {
        kfree(node);
        return ret;
      }
      /* 将新节点挂载到父节点。 */
      trust_proc_attach_node_locked(node, parent);
    } else if (node->parent != parent) {
      /* 如果进程已存在，则将其挂载到父节点。 */
      trust_proc_attach_node_locked(node, parent);
    }
    /* 更新父节点。 */
    parent = node;
  }

  if (!node) {
    return -EINVAL;
  }

  /* 标记进程为显式添加。 */
  node->is_explicit = true;
  /* 设置是否将进程组内的所有进程都添加到白名单。 */
  node->is_tree = is_tree;

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
trust_proc_alloc_parsed_node(pid_t pid, bool is_tree, bool is_explicit) {
  struct trust_proc_parsed_node *node;

  node = kzalloc(sizeof(*node), GFP_KERNEL);
  if (!node) {
    return NULL;
  }

  node->pid = pid;
  node->is_tree = is_tree;
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
  bool is_tree = true;
  bool is_explicit = true;
  pid_t pid;
  int ret;

  if (!cursor || !*cursor || !out) {
    return -EINVAL;
  }

  if (depth >= PID_MAX_LIMIT) {
    return -E2BIG;
  }

  ret = trust_proc_parse_number(cursor, &pid);
  if (ret) {
    return ret;
  }

  trust_proc_skip_spaces(cursor);
  if (**cursor == '*' || **cursor == '!') {
    is_tree = (**cursor == '*');
    (*cursor)++;
  }

  trust_proc_skip_spaces(cursor);
  if (**cursor == '?') {
    is_explicit = false;
    (*cursor)++;
  }

  node = trust_proc_alloc_parsed_node(pid, is_tree, is_explicit);
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
  node->is_tree = parsed->is_tree;

  ret = trust_proc_insert_node_locked(node);
  if (ret) {
    kfree(node);
    return ret;
  }
  trust_proc_attach_node_locked(node, parent);

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

/* 添加进程[组]到白名单。 */
int trust_proc_add(pid_t pid, bool is_tree) {
  pid_t *lineage = NULL;
  size_t depth = 0;
  int ret;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    pr_warn("trust_proc: invalid pid=%d\n", pid);
    return -EINVAL;
  }

  ret = trust_proc_collect_lineage(pid, &lineage, &depth);
  if (ret) {
    return ret;
  }

  write_lock(&g_rwlock);
  ret = trust_proc_upsert_chain_locked(lineage, depth, is_tree);
  if (!ret) {
    pr_info("trust_proc: added pid=%d %s\n", pid, is_tree ? "*" : "");
  }
  write_unlock(&g_rwlock);
  kfree(lineage);
  return ret;
}

/* 将进程[组]从白名单中移除。 */
int trust_proc_remove(pid_t pid, bool is_tree) {
  struct trust_proc_node *node;
  int ret = 0;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    pr_warn("trust_proc: invalid pid=%d\n", pid);
    return -EINVAL;
  }

  write_lock(&g_rwlock);
  node = trust_proc_lookup_locked(pid);
  if (!node || !node->is_explicit) {
    pr_warn("trust_proc: pid=%d not found\n", pid);
    ret = -ENOENT;
    goto out_unlock;
  }

  node->is_explicit = false;
  node->is_tree = false;

  trust_proc_prune_locked(node);
  pr_info("trust_proc: removed pid=%d %s\n", pid, is_tree ? "*" : "");

out_unlock:
  write_unlock(&g_rwlock);
  return ret;
}

/* 查询白名单，监听器会跳过这些 PID。 */
bool trust_proc_contains(pid_t pid) {
  struct trust_proc_node *node;
  pid_t *lineage = NULL;
  size_t depth = 0;
  bool contains = false;
  int ret;
  size_t i;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return false;
  }

  read_lock(&g_rwlock);
  node = trust_proc_lookup_locked(pid);
  if (node) {
    contains = trust_proc_node_contains(node);
  }
  read_unlock(&g_rwlock);

  if (contains) {
    return true;
  }

  /* 如果进程不在白名单中，则检查其祖先进程是否在白名单中。 */
  ret = trust_proc_collect_lineage(pid, &lineage, &depth);
  if (ret) {
    return false;
  }

  read_lock(&g_rwlock);
  for (i = 0; i < depth; ++i) {
    struct trust_proc_node *ancestor = trust_proc_lookup_locked(lineage[i]);
    if (!ancestor || !ancestor->is_explicit) {
      continue;
    }
    if (i == 0 || ancestor->is_tree) {
      contains = true;
      break;
    }
  }
  read_unlock(&g_rwlock);

  kfree(lineage);
  return contains;
}

static int trust_proc_apply_flat_list(const pid_t *pids, size_t count) {
  struct trust_proc_lineage_cache {
    pid_t *lineage;
    size_t depth;
  };
  struct trust_proc_lineage_cache *cache;
  size_t i;
  int ret = 0;

  cache = kcalloc(count, sizeof(*cache), GFP_KERNEL);
  if (!cache) {
    return -ENOMEM;
  }

  for (i = 0; i < count; ++i) {
    cache[i].lineage = NULL;
  }

  for (i = 0; i < count; ++i) {
    ret = trust_proc_collect_lineage(pids[i], &cache[i].lineage,
                                     &cache[i].depth);
    if (ret) {
      goto out_free;
    }
  }

  write_lock(&g_rwlock);
  for (i = 0; i < count; ++i) {
    ret =
        trust_proc_upsert_chain_locked(cache[i].lineage, cache[i].depth, true);
    if (ret) {
      break;
    }
  }
  write_unlock(&g_rwlock);

out_free:
  for (i = 0; i < count; ++i) {
    kfree(cache[i].lineage);
  }
  kfree(cache);
  return ret;
}

static int trust_proc_apply_tree_string(char *input) {
  LIST_HEAD(parsed_roots);
  size_t explicit_count = 0;
  int ret;

  ret = trust_proc_parse_tree(input, &parsed_roots, &explicit_count);
  if (ret) {
    trust_proc_free_parsed_tree(&parsed_roots);
    return ret;
  }

  write_lock(&g_rwlock);
  trust_proc_clear_locked();
  ret = trust_proc_apply_parsed_roots_locked(&parsed_roots);
  if (ret) {
    trust_proc_clear_locked();
  }
  write_unlock(&g_rwlock);

  trust_proc_free_parsed_tree(&parsed_roots);
  if (!ret) {
    pr_info("trust_proc: updated (%zu entries)\n", explicit_count);
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

  buf = kstrdup(val, GFP_KERNEL);
  if (!buf) {
    return -ENOMEM;
  }

  trimmed = strim(buf);
  if (!trimmed || !*trimmed) {
    write_lock(&g_rwlock);
    trust_proc_clear_locked();
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

  ret = parse_proc_list(trimmed, &parsed, &count);
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
  size_t offset = 0;
  bool first = true;
  int ret = 0;
  struct rb_node *rbnode;
  size_t buflen = PAGE_SIZE;

  if (!buffer) {
    return -EINVAL;
  }

  buffer[0] = '\0';

  read_lock(&g_rwlock);
  rbnode = rb_first(&g_trust_proc_root);
  while (rbnode) {
    struct trust_proc_node *node =
        rb_entry(rbnode, struct trust_proc_node, rb);

    if (!node->parent) {
      ret = trust_proc_format_node(node, buffer, buflen, &offset, first);
      if (ret) {
        break;
      }
      first = false;
    }
    rbnode = rb_next(rbnode);
  }
  read_unlock(&g_rwlock);

  if (ret) {
    if (buflen) {
      buffer[min(offset, buflen - 1)] = '\0';
    }
    return ret;
  }

  if (offset >= buflen) {
    if (buflen) {
      buffer[buflen - 1] = '\0';
      return buflen - 1;
    }
    return 0;
  }

  buffer[offset] = '\0';
  return offset;
}

static const struct kernel_param_ops trust_proc_ops = {
    .set = trust_proc_param_set,
    .get = trust_proc_param_get,
};

module_param_cb(trust_proc, &trust_proc_ops, NULL, 0644);
MODULE_PARM_DESC(trust_proc,
                 "Tree-shaped trust-process (pid[*|!][?] (children...))");
