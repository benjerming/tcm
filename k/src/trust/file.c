#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/moduleparam.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include "tcm/trust/file.h"

/*
 * 文件白名单实现
 *  - 使用多层红黑树模拟文件系统层级；目录节点拥有子树，文件节点为叶子
 *  -
 * 目录节点可标记为白名单条目(is_trust_entry)，从而标记该目录及子树为白名单
 *  - 使用读写锁保护并发访问，并限制最大允许条目数量
 */

enum trust_file_node_type {
  TRUST_FILE_NODE_DIR = 0,
  TRUST_FILE_NODE_FILE = 1,
};

struct trust_file_node {
  struct rb_node rb;
  struct rb_root children;
  struct trust_file_node *parent;
  enum trust_file_node_type type;
  bool is_trust_entry;
  size_t name_len;
  char name[];
};

struct path_segment {
  const char *start;
  size_t len;
};

static struct trust_file_node *trust_file_root;
static DEFINE_RWLOCK(trust_file_lock);
static size_t trust_file_count;

/* 在 sibling 红黑树中比较节点名称，按字典序定位。 */
static int trust_file_name_cmp(const char *name, size_t name_len,
                               const struct trust_file_node *node) {
  size_t cmp_len = min(name_len, node->name_len);
  int cmp = memcmp(name, node->name, cmp_len);

  if (cmp) {
    return cmp;
  }

  if (name_len == node->name_len) {
    return 0;
  }

  return name_len < node->name_len ? -1 : 1;
}

/* 分配新节点：目录节点保留子树根，文件节点为叶子。 */
static struct trust_file_node *
trust_file_node_alloc(const char *name, size_t name_len,
                      enum trust_file_node_type type, gfp_t gfp) {
  size_t alloc_size = sizeof(struct trust_file_node) + name_len + 1;
  struct trust_file_node *node = kzalloc(alloc_size, gfp);

  if (!node) {
    return NULL;
  }

  node->children = RB_ROOT;
  node->parent = NULL;
  node->type = type;
  node->is_trust_entry = false;
  node->name_len = name_len;

  if (name_len) {
    memcpy(node->name, name, name_len);
  }
  node->name[name_len] = '\0';

  return node;
}

/* 在父目录的红黑树中查找指定名称的子节点。 */
static struct trust_file_node *
trust_file_lookup_child(struct trust_file_node *parent, const char *name,
                        size_t name_len) {
  struct rb_node *node;

  if (!parent) {
    return NULL;
  }

  node = parent->children.rb_node;
  while (node) {
    struct trust_file_node *entry = rb_entry(node, struct trust_file_node, rb);
    int cmp = trust_file_name_cmp(name, name_len, entry);

    if (cmp < 0) {
      node = node->rb_left;
    } else if (cmp > 0) {
      node = node->rb_right;
    } else {
      return entry;
    }
  }

  return NULL;
}

/* 将新节点插入父目录的红黑树，必要时保持自平衡。 */
static int trust_file_insert_child(struct trust_file_node *parent,
                                   struct trust_file_node *child) {
  struct rb_node **link = &parent->children.rb_node;
  struct rb_node *rb_parent = NULL;

  while (*link) {
    struct trust_file_node *entry = rb_entry(*link, struct trust_file_node, rb);
    int cmp = trust_file_name_cmp(child->name, child->name_len, entry);

    rb_parent = *link;
    if (cmp < 0) {
      link = &(*link)->rb_left;
    } else if (cmp > 0) {
      link = &(*link)->rb_right;
    } else {
      return -EEXIST;
    }
  }

  child->parent = parent;
  rb_link_node(&child->rb, rb_parent, link);
  rb_insert_color(&child->rb, &parent->children);
  return 0;
}

/* 递归释放节点及其子树，释放内核内存。 */
static void trust_file_node_free_recursive(struct trust_file_node *node) {
  struct trust_file_node *child, *tmp;

  if (!node) {
    return;
  }

  /* 使用后序遍历安全地删除所有子节点 */
  rbtree_postorder_for_each_entry_safe(child, tmp, &node->children, rb) {
    trust_file_node_free_recursive(child);
  }

  kfree(node);
}

static void trust_file_clear_locked(void) {
  if (!trust_file_root) {
    trust_file_count = 0;
    return;
  }

  trust_file_node_free_recursive(trust_file_root);
  trust_file_root = NULL;
  trust_file_count = 0;
}

/* 标准化路径字符串，返回是否为目录并去除冗余分隔符。 */
static int trust_file_normalize(const char *input, char *out, size_t outlen,
                                size_t *normalized_len, bool *is_dir) {
  char *buffer;
  char *trimmed;
  size_t len;
  bool has_trailing_slash = false;
  int ret;

  if (!input || !out || !outlen) {
    return -EINVAL;
  }

  buffer = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!buffer) {
    return -ENOMEM;
  }

  ret = strscpy(buffer, input, PATH_MAX);
  if (ret < 0) {
    goto out_free;
  }

  trimmed = strim(buffer);
  if (!*trimmed) {
    ret = -EINVAL;
    goto out_free;
  }

  if (trimmed != buffer) {
    size_t trimmed_len = strnlen(trimmed, PATH_MAX);
    memmove(buffer, trimmed, trimmed_len + 1);
  }

  len = strnlen(buffer, PATH_MAX);
  if (!len) {
    ret = -EINVAL;
    goto out_free;
  }

  if (len > 1) {
    while (len > 1 && buffer[len - 1] == '/') {
      buffer[--len] = '\0';
      has_trailing_slash = true;
    }
  }

  if (buffer[0] != '/') {
    ret = -EINVAL;
    goto out_free;
  }

  ret = strscpy(out, buffer, outlen);
  if (ret < 0) {
    goto out_free;
  }

  if (normalized_len) {
    *normalized_len = strnlen(out, outlen);
  }
  if (is_dir) {
    if (len == 1 && buffer[0] == '/') {
      *is_dir = true;
    } else {
      *is_dir = has_trailing_slash;
    }
  }

  ret = 0;

out_free:
  kfree(buffer);
  return ret;
}

/*
 * 将标准化路径拆分为逐级段落：
 *  - 例如 /a/b/c 拆成 ["a","b","c"]
 *  - 用于逐层在红黑树中查找或创建节点
 */
static int trust_file_collect_segments(const char *path,
                                       struct path_segment **segments_out,
                                       size_t *count_out) {
  const char *cursor;
  size_t count = 0;
  size_t idx = 0;
  struct path_segment *segments = NULL;

  if (!path || path[0] != '/') {
    return -EINVAL;
  }

  cursor = path + 1;
  while (*cursor) {
    const char *next = strchrnul(cursor, '/');

    if (next == cursor) {
      if (*next == '\0') {
        break;
      }
      cursor = next + 1;
      continue;
    }

    count++;
    if (*next == '\0') {
      break;
    }
    cursor = next + 1;
  }

  if (!count) {
    if (segments_out) {
      *segments_out = NULL;
    }
    if (count_out) {
      *count_out = 0;
    }
    return 0;
  }

  segments = kcalloc(count, sizeof(struct path_segment), GFP_KERNEL);
  if (!segments) {
    return -ENOMEM;
  }

  cursor = path + 1;
  while (*cursor && idx < count) {
    const char *next = strchrnul(cursor, '/');

    if (next == cursor) {
      if (*next == '\0') {
        break;
      }
      cursor = next + 1;
      continue;
    }

    segments[idx].start = cursor;
    segments[idx].len = next - cursor;
    idx++;
    if (*next == '\0') {
      break;
    }
    cursor = next + 1;
  }

  if (count_out) {
    *count_out = idx;
  }
  if (segments_out) {
    *segments_out = segments;
  } else {
    kfree(segments);
  }

  return 0;
}

static char *trust_file_normalize_alloc(const char *path,
                                        size_t *normalized_len) {
  char *normalized;
  int ret;

  if (!path || !*path) {
    return NULL;
  }

  normalized = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!normalized) {
    return NULL;
  }

  ret = trust_file_normalize(path, normalized, PATH_MAX, normalized_len, NULL);
  if (ret) {
    kfree(normalized);
    return NULL;
  }

  return normalized;
}

/* 自底向上清理空目录，保持树结构紧凑。 */
static void trust_file_prune_from(struct trust_file_node *node) {
  while (node && node->parent) {
    if (node->is_trust_entry) {
      break;
    }
    if (!RB_EMPTY_ROOT(&node->children)) {
      break;
    }

    struct trust_file_node *parent = node->parent;

    rb_erase(&node->rb, &parent->children);
    kfree(node);
    node = parent;
  }
}

/* 初始化文件白名单。 */
int trust_file_init(void) {
  struct trust_file_node *root;
  int ret = 0;

  root = trust_file_node_alloc("", 0, TRUST_FILE_NODE_DIR, GFP_KERNEL);
  if (!root) {
    return -ENOMEM;
  }

  write_lock(&trust_file_lock);
  trust_file_clear_locked();
  trust_file_root = root;
  trust_file_count = 0;
  write_unlock(&trust_file_lock);

  return ret;
}

/* 销毁文件白名单。 */
void trust_file_exit(void) {
  write_lock(&trust_file_lock);
  trust_file_clear_locked();
  write_unlock(&trust_file_lock);
}

/* 添加白名单文件或目录树(目录以 '/' 结尾)。 */
int trust_file_add(const char *path) {
  struct trust_file_node **created_nodes = NULL;
  /* node 指向当前遍历节点，child 为查找到/新建的子节点。 */
  struct trust_file_node *node;
  struct trust_file_node *child;
  struct path_segment *segments = NULL;
  size_t created_count = 0;
  size_t segment_count = 0;
  size_t normalized_len = 0;
  bool target_is_dir = false;
  char *normalized;
  int ret;

  normalized = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!normalized) {
    return -ENOMEM;
  }

  /* 先对输入路径进行标准化处理，并识别目标类型。 */
  ret = trust_file_normalize(path, normalized, PATH_MAX, &normalized_len,
                             &target_is_dir);
  if (ret) {
    goto out_free;
  }

  ret = trust_file_collect_segments(normalized, &segments, &segment_count);
  if (ret) {
    goto out_free;
  }

  if (segment_count) {
    // NOLINTNEXTLINE(bugprone-sizeof-expression): 这里需要分配指针数组
    created_nodes = kcalloc(segment_count, sizeof(*created_nodes), GFP_KERNEL);
    if (!created_nodes) {
      ret = -ENOMEM;
      goto out_free;
    }
  }

  write_lock(&trust_file_lock);
  if (!trust_file_root) {
    ret = -EINVAL;
    goto out_unlock;
  }

  /* 根目录是特殊情况：直接设置标记即可，无需遍历。 */
  if (normalized_len == 1 && normalized[0] == '/') {
    if (trust_file_root->is_trust_entry) {
      ret = 0;
      goto out_unlock;
    }
    trust_file_root->is_trust_entry = true;
    trust_file_count++;
    pr_info("trust_file: added directory \"/\" (count=%zu)\n",
            trust_file_count);
    ret = 0;
    goto out_unlock;
  }

  node = trust_file_root;
  size_t i;
  for (i = 0; i < segment_count; i++) {
    bool last = (i == segment_count - 1);
    enum trust_file_node_type expected_type =
        last && !target_is_dir ? TRUST_FILE_NODE_FILE : TRUST_FILE_NODE_DIR;

    /* 查找当前段的子节点，必要时创建新的节点并挂载到树上。 */
    child = trust_file_lookup_child(node, segments[i].start, segments[i].len);
    if (!child) {
      child = trust_file_node_alloc(segments[i].start, segments[i].len,
                                    expected_type, GFP_ATOMIC);
      if (!child) {
        ret = -ENOMEM;
        goto rollback;
      }

      ret = trust_file_insert_child(node, child);
      if (ret) {
        kfree(child);
        goto rollback;
      }

      created_nodes[created_count++] = child;
    } else {
      if (!last && child->type != TRUST_FILE_NODE_DIR) {
        ret = -ENOTDIR;
        goto rollback;
      }
      if (last && target_is_dir && child->type != TRUST_FILE_NODE_DIR) {
        ret = -ENOTDIR;
        goto rollback;
      }
      if (last && !target_is_dir && child->type != TRUST_FILE_NODE_FILE) {
        ret = -EISDIR;
        goto rollback;
      }
    }

    node = child;
  }

  if (!node) {
    ret = -EINVAL;
    goto rollback;
  }

  if (node->is_trust_entry) {
    ret = 0;
    goto out_unlock;
  }

  node->is_trust_entry = true;
  trust_file_count++;
  pr_info("trust_file: added %s \"%s\" (count=%zu)\n",
          node->type == TRUST_FILE_NODE_DIR ? "directory" : "file", normalized,
          trust_file_count);
  ret = 0;
  goto out_unlock;

rollback:
  while (created_count) {
    /* 回滚阶段：释放在失败前新建的节点，避免内存泄漏。 */
    struct trust_file_node *created = created_nodes[--created_count];
    if (!created) {
      continue;
    }

    if (!RB_EMPTY_ROOT(&created->children) || created->is_trust_entry) {
      continue;
    }

    if (created->parent) {
      rb_erase(&created->rb, &created->parent->children);
    }
    kfree(created);
  }

out_unlock:
  write_unlock(&trust_file_lock);

out_free:
  kfree(created_nodes);
  kfree(segments);
  kfree(normalized);
  return ret;
}

/* 移除白名单文件或目录树(目录以 '/' 结尾)。 */
int trust_file_remove(const char *path) {
  struct trust_file_node *node;
  /* parent 用于在删除文件节点后回溯修剪空目录。 */
  struct trust_file_node *parent;
  struct path_segment *segments = NULL;
  size_t segment_count = 0;
  size_t normalized_len = 0;
  bool target_is_dir = false;
  char *normalized;
  int ret;

  normalized = kmalloc(PATH_MAX, GFP_KERNEL);
  if (!normalized) {
    return -ENOMEM;
  }

  /* 与添加逻辑一致，确保对同一路径进行相同的标准化处理。 */
  ret = trust_file_normalize(path, normalized, PATH_MAX, &normalized_len,
                             &target_is_dir);
  if (ret) {
    goto out_free;
  }

  ret = trust_file_collect_segments(normalized, &segments, &segment_count);
  if (ret) {
    goto out_free;
  }

  write_lock(&trust_file_lock);
  if (!trust_file_root) {
    ret = -EINVAL;
    goto out_unlock;
  }

  /* 根目录的删除只需要重置白名单条目标记。 */
  if (normalized_len == 1 && normalized[0] == '/') {
    if (!trust_file_root->is_trust_entry) {
      ret = -ENOENT;
      goto out_unlock;
    }
    trust_file_root->is_trust_entry = false;
    if (trust_file_count > 0) {
      trust_file_count--;
    }
    pr_info("trust_file: removed directory \"/\" (count=%zu)\n",
            trust_file_count);
    ret = 0;
    goto out_unlock;
  }

  node = trust_file_root;
  size_t i;
  for (i = 0; i < segment_count; i++) {
    bool last = (i == segment_count - 1);

    /* 自顶向下查找链路；如遇缺失立即返回未找到。 */
    node = trust_file_lookup_child(node, segments[i].start, segments[i].len);
    if (!node) {
      ret = -ENOENT;
      goto out_unlock;
    }

    if (!last && node->type != TRUST_FILE_NODE_DIR) {
      ret = -ENOTDIR;
      goto out_unlock;
    }
  }

  if (!node) {
    /* 兜底检查：理论上不会触发，仍返回未找到以防逻辑异常。 */
    ret = -ENOENT;
    goto out_unlock;
  }

  if (target_is_dir) {
    if (node->type != TRUST_FILE_NODE_DIR) {
      ret = -ENOTDIR;
      goto out_unlock;
    }
    if (!node->is_trust_entry) {
      ret = -ENOENT;
      goto out_unlock;
    }

    node->is_trust_entry = false;
    if (trust_file_count > 0) {
      trust_file_count--;
    }
    pr_info("trust_file: removed directory \"%s\" (count=%zu)\n", normalized,
            trust_file_count);
    trust_file_prune_from(node);
  } else {
    if (node->type != TRUST_FILE_NODE_FILE) {
      ret = -EISDIR;
      goto out_unlock;
    }
    if (!node->is_trust_entry) {
      ret = -ENOENT;
      goto out_unlock;
    }

    parent = node->parent;
    rb_erase(&node->rb, &parent->children);
    kfree(node);
    if (trust_file_count > 0) {
      trust_file_count--;
    }
    pr_info("trust_file: removed file \"%s\" (count=%zu)\n", normalized,
            trust_file_count);
    trust_file_prune_from(parent);
  }

  ret = 0;

out_unlock:
  write_unlock(&trust_file_lock);

out_free:
  kfree(segments);
  kfree(normalized);
  return ret;
}

/*
 * 在持有读锁的前提下检查标准化路径是否被允许。
 *  - 支持目录节点的递归继承：父目录是白名单条目时，子路径一并放行
 *  - 对于缺失节点，返回最近一个白名单目录前缀的继承状态
 */
static bool trust_file_contains_locked(const char *normalized,
                                       size_t normalized_len) {
  struct trust_file_node *node;
  bool inherited_permission;
  const char *cursor;

  node = trust_file_root;
  if (!node) {
    return false;
  }

  inherited_permission = node->is_trust_entry;

  if (normalized_len == 1 && normalized[0] == '/') {
    return inherited_permission;
  }

  cursor = normalized + 1;
  while (*cursor) {
    const char *next = strchrnul(cursor, '/');
    size_t seg_len = next - cursor;

    if (!seg_len) {
      if (*next == '\0') {
        break;
      }
      cursor = next + 1;
      continue;
    }

    node = trust_file_lookup_child(node, cursor, seg_len);
    if (!node) {
      return inherited_permission;
    }

    if (node->type == TRUST_FILE_NODE_DIR && node->is_trust_entry) {
      inherited_permission = true;
    }

    if (*next == '\0') {
      if (node->is_trust_entry) {
        return true;
      }
      return inherited_permission;
    }

    if (node->type != TRUST_FILE_NODE_DIR) {
      return inherited_permission;
    }

    cursor = next + 1;
  }

  return inherited_permission;
}

/* 判断路径是否在白名单中或是否在白名单目录下(目录以 '/' 结尾)。 */
bool trust_file_contains(const char *path) {
  char *normalized;
  size_t normalized_len = 0;
  bool contains = false;

  normalized = trust_file_normalize_alloc(path, &normalized_len);
  if (!normalized) {
    return false;
  }

  read_lock(&trust_file_lock);
  if (!trust_file_root || !trust_file_count) {
    contains = false;
    goto out_unlock;
  }

  contains = trust_file_contains_locked(normalized, normalized_len);

out_unlock:
  read_unlock(&trust_file_lock);
  kfree(normalized);
  return contains;
}

static int trust_file_param_set(const char *val,
                                const struct kernel_param *kp) {
  return -EPERM;
}

/* 将格式化字符串安全追加到输出缓冲区，并维护写入统计。 */
static void trust_file_param_append(char **cursor, size_t *remaining,
                                    size_t *total, const char *str) {
  size_t written;

  if (!*remaining) {
    return;
  }

  written = scnprintf(*cursor, *remaining, "%s", str);
  if (!written) {
    *remaining = 0;
    return;
  }

  *cursor += written;
  *total += written;
  if (*remaining > written) {
    *remaining -= written;
  } else {
    *remaining = 0;
  }
}

/*
 * 递归输出白名单树：
 *  - 根节点深度为 0，直接打印 "/" 作为起点
 *  - 每一层使用两个空格缩进，目录以 '/' 结尾
 *  - 白名单条目节点追加 " *" 标记，便于快速识别放行范围
 */
static void trust_file_emit_tree(struct trust_file_node *node, char **cursor,
                                 size_t *remaining, size_t *total,
                                 unsigned depth) {
  struct rb_node *rb;
  unsigned i;

  if (!node || !*remaining) {
    return;
  }

  if (depth == 0) {
    trust_file_param_append(cursor, remaining, total, "/");
    if (node->is_trust_entry) {
      trust_file_param_append(cursor, remaining, total, " *");
    }
    trust_file_param_append(cursor, remaining, total, "\n");
  } else {
    for (i = 0; i < depth && *remaining; ++i) {
      trust_file_param_append(cursor, remaining, total, "  ");
    }
    if (!*remaining) {
      return;
    }

    trust_file_param_append(cursor, remaining, total, node->name);
    if (!*remaining) {
      return;
    }

    if (node->type == TRUST_FILE_NODE_DIR) {
      trust_file_param_append(cursor, remaining, total, "/");
      if (!*remaining) {
        return;
      }
    }

    if (node->is_trust_entry) {
      trust_file_param_append(cursor, remaining, total, " *");
      if (!*remaining) {
        return;
      }
    }

    trust_file_param_append(cursor, remaining, total, "\n");
  }

  for (rb = rb_first(&node->children); rb && *remaining; rb = rb_next(rb)) {
    struct trust_file_node *child = rb_entry(rb, struct trust_file_node, rb);

    trust_file_emit_tree(child, cursor, remaining, total, depth + 1);
  }
}

static int trust_file_param_get(char *buffer, const struct kernel_param *kp) {
  char *cursor = buffer;
  size_t remaining = PAGE_SIZE;
  size_t total = 0;
  bool empty;

  if (!buffer) {
    return -EINVAL;
  }

  read_lock(&trust_file_lock);
  if (!trust_file_root) {
    /* 白名单尚未初始化时返回占位信息，避免空指针访问。 */
    total = scnprintf(buffer, PAGE_SIZE, "<uninitialized>\n");
    read_unlock(&trust_file_lock);
    return (int)total;
  }

  empty = (trust_file_count == 0);
  trust_file_emit_tree(trust_file_root, &cursor, &remaining, &total, 0);
  if (empty && remaining) {
    /* 仅根节点存在，但没有任何允许条目。 */
    trust_file_param_append(&cursor, &remaining, &total, "(empty)\n");
  }

  read_unlock(&trust_file_lock);
  return (int)total;
}

static const struct kernel_param_ops trust_file_ops = {
    .set = trust_file_param_set,
    .get = trust_file_param_get,
};

module_param_cb(trust_file, &trust_file_ops, NULL, 0444);
MODULE_PARM_DESC(trust_file, "List of files and directories "
                             "allowed by the event listeners.");