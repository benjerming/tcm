#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "tcm/api.h"
#include "tcm/genl.h"
#include "tcm/kprobes/file.h"
#include "tcm/whitelist/file.h"
#include "tcm/whitelist/pid.h"

/*
 * 通用 Netlink 核心：
 *  - 负责注册 genetlink family、命令与多播组
 *  - 将来自监听器的事件转发给用户态
 *  - 提供白名单与统计信息的控制接口
 */

typedef struct {
  struct list_head node;
  u32 portid;
} genl_core_client_t;

/* genetlink 核心上下文，封装 family、ops、监听器等状态。 */
struct genl_core {
  struct nla_policy policy[TCM_GENL_ATTR_MAX];
  struct genl_multicast_group mcgrps[TCM_GENL_MCGRP_COUNT];
  struct genl_ops ops[TCM_GENL_CMD_OPS_COUNT];
  struct genl_family family;
  file_listener_t *file_listener;
  struct list_head clients;
  spinlock_t clients_lock;
};

static int genl_core_get_from_info(struct genl_info *info,
                                   genl_core_t **out_core) {
  genl_core_t *core;

  if (!info || !info->family) {
    pr_warn("%s: invalid genl_info\n", __func__);
    return -EINVAL;
  }

  core = container_of(info->family, genl_core_t, family);
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
  }

  if (out_core) {
    *out_core = core;
  }

  return 0;
}

static bool genl_core_clients_contains_locked(genl_core_t *core, u32 portid) {
  genl_core_client_t *client;

  list_for_each_entry(client, &core->clients, node) {
    if (client->portid == portid) {
      return true;
    }
  }

  return false;
}

static bool genl_core_clients_contains(genl_core_t *core, u32 portid) {
  unsigned long flags;
  bool found;

  if (!core) {
    return false;
  }

  spin_lock_irqsave(&core->clients_lock, flags);
  found = genl_core_clients_contains_locked(core, portid);
  spin_unlock_irqrestore(&core->clients_lock, flags);

  return found;
}

static int genl_core_clients_add(genl_core_t *core, u32 portid) {
  genl_core_client_t *client;
  unsigned long flags;

  if (!core) {
    return -EINVAL;
  }

  spin_lock_irqsave(&core->clients_lock, flags);
  if (genl_core_clients_contains_locked(core, portid)) {
    spin_unlock_irqrestore(&core->clients_lock, flags);
    return -EEXIST;
  }
  spin_unlock_irqrestore(&core->clients_lock, flags);

  client = kmalloc(sizeof(*client), GFP_KERNEL);
  if (!client) {
    return -ENOMEM;
  }

  client->portid = portid;
  INIT_LIST_HEAD(&client->node);

  spin_lock_irqsave(&core->clients_lock, flags);
  if (genl_core_clients_contains_locked(core, portid)) {
    spin_unlock_irqrestore(&core->clients_lock, flags);
    kfree(client);
    return -EEXIST;
  }

  list_add_tail(&client->node, &core->clients);
  spin_unlock_irqrestore(&core->clients_lock, flags);

  return 0;
}

static void genl_core_clients_clear(genl_core_t *core) {
  genl_core_client_t *client, *tmp;
  unsigned long flags;

  if (!core) {
    return;
  }

  spin_lock_irqsave(&core->clients_lock, flags);
  list_for_each_entry_safe(client, tmp, &core->clients, node) {
    list_del(&client->node);
    kfree(client);
  }
  spin_unlock_irqrestore(&core->clients_lock, flags);
}

static int genl_core_require_client_login(struct genl_info *info,
                                          genl_core_t **out_core) {
  genl_core_t *core;
  int ret;

  ret = genl_core_get_from_info(info, &core);
  if (ret) {
    return ret;
  }

  if (!genl_core_clients_contains(core, info->snd_portid)) {
    pr_warn("%s: client pid=%d not logged in\n", __func__, info->snd_portid);
    return -EACCES;
  }

  if (out_core) {
    *out_core = core;
  }

  return 0;
}

/* 处理客户端注册请求，将调用方 PID 加入白名单。 */
static int genl_core_handle_login(struct sk_buff *skb, struct genl_info *info) {
  genl_core_t *core;
  int ret;
  const char *key = NULL;

  ret = genl_core_get_from_info(info, &core);
  if (ret) {
    return ret;
  }

  if (info->attrs[TCM_GENL_ATTR_KEY]) {
    key = (const char *)nla_data(info->attrs[TCM_GENL_ATTR_KEY]);
  }
  if (!key) {
    pr_warn("%s: invalid key\n", __func__);
    return -EINVAL;
  }

  if (strcmp(key, "1234567890") != 0) {
    pr_warn("%s: invalid key\n", __func__);
    return -EINVAL;
  }

  ret = genl_core_clients_add(core, info->snd_portid);
  if (ret != 0 && ret != -EEXIST) {
    pr_warn("%s: failed to add client pid=%d: %d\n", __func__, info->snd_portid,
            ret);
    return ret;
  }

  ret = pid_whitelist_add(info->snd_portid);
  if (ret != 0 && ret != -EEXIST) {
    pr_warn("%s: pid_whitelist_add failed for pid=%d: %d\n", __func__,
            info->snd_portid, ret);
    return ret;
  }

  pr_info("%s: registered client pid=%d\n", __func__, info->snd_portid);
  return 0;
}

/* 应答文件监听器统计信息的查询命令。 */
static int genl_core_handle_get_file_stats(struct sk_buff *skb,
                                           struct genl_info *info) {
  genl_core_t *core;
  file_listener_stats_t stats;
  struct sk_buff *msg;
  void *msg_head;
  int ret;
  size_t top_pids_len;

  ret = genl_core_require_client_login(info, &core);
  if (ret) {
    return ret;
  }

  if (!core->file_listener) {
    pr_warn("%s: file_listener not registered\n", __func__);
    return -ENODEV;
  }

  /* 向文件监听器请求最新的统计数据快照。 */
  ret = file_listener_get_stats(core->file_listener, &stats);
  if (ret) {
    pr_warn("%s: file_listener_get_stats failed: %d\n", __func__, ret);
    return ret;
  }

  /* 构造应答报文，携带统计信息返回给请求方。 */
  msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
  if (!msg) {
    pr_warn("%s: failed to allocate reply skb\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(msg, info->snd_portid, info->snd_seq, info->family, 0,
                         TCM_GENL_CMD_FILE_STATS_EVENT);
  if (!msg_head) {
    pr_warn("%s: genlmsg_put failed\n", __func__);
    nlmsg_free(msg);
    return -EMSGSIZE;
  }

  ret = nla_put_u32(msg, TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE,
                    stats.pid_table_size);
  if (ret) {
    pr_warn("%s: nla_put failed for pid_table_size: %d\n", __func__, ret);
    goto err_cancel;
  }

  ret = nla_put_u32(msg, TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT,
                    stats.pid_entry_count);
  if (ret) {
    pr_warn("%s: nla_put failed for pid_entry_count: %d\n", __func__, ret);
    goto err_cancel;
  }

  ret = nla_put_u32(msg, TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT,
                    stats.file_entry_count);
  if (ret) {
    pr_warn("%s: nla_put failed for file_entry_count: %d\n", __func__, ret);
    goto err_cancel;
  }

  ret = nla_put_u32(msg, TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT,
                    stats.top_pid_count);
  if (ret) {
    pr_warn("%s: nla_put failed for top_pid_count: %d\n", __func__, ret);
    goto err_cancel;
  }

  top_pids_len = stats.top_pid_count * sizeof(file_listener_pid_stat_t);
  /* 附带热度最高的 PID 列表，便于用户态做进一步分析。 */
  ret = nla_put(msg, TCM_GENL_ATTR_FILE_STATS_TOP_PIDS, top_pids_len,
                stats.top_pids);
  if (ret) {
    pr_warn("%s: nla_put failed for top_pids: %d\n", __func__, ret);
    goto err_cancel;
  }

  genlmsg_end(msg, msg_head);

  ret = genlmsg_reply(msg, info);
  if (ret) {
    pr_warn("%s: genlmsg_reply failed: %d\n", __func__, ret);
  }

  return ret;

err_cancel:
  genlmsg_cancel(msg, msg_head);
  nlmsg_free(msg);
  return ret;
}

/* 从 Netlink 报文解析白名单路径属性。 */
static int genl_core_parse_file_whitelist(struct genl_info *info,
                                          const char **path) {
  if (!info || !path) {
    return -EINVAL;
  }

  if (!info->attrs[TCM_GENL_ATTR_PATH1]) {
    pr_warn("%s: missing TCM_GENL_ATTR_PATH1 attribute\n", __func__);
    return -EINVAL;
  }

  *path = nla_data(info->attrs[TCM_GENL_ATTR_PATH1]);
  if (!*path) {
    pr_warn("%s: invalid whitelist path attribute\n", __func__);
    return -EINVAL;
  }

  return 0;
}

/* 处理添加白名单路径的 Netlink 命令。 */
static int genl_core_handle_file_whitelist_add(struct sk_buff *skb,
                                               struct genl_info *info) {
  const char *path;
  int ret;

  ret = genl_core_require_client_login(info, NULL);
  if (ret) {
    return ret;
  }

  /* 从报文中解析出目标白名单路径。 */
  ret = genl_core_parse_file_whitelist(info, &path);
  if (ret) {
    pr_warn("%s: failed to parse add whitelist request: %d\n", __func__, ret);
    return ret;
  }

  ret = file_whitelist_add(path);
  if (ret) {
    pr_warn("%s: file_whitelist_add failed for \"%s\": %d\n", __func__, path,
            ret);
  }
  return ret;
}

/* 处理移除白名单路径的 Netlink 命令。 */
static int genl_core_handle_file_whitelist_remove(struct sk_buff *skb,
                                                  struct genl_info *info) {
  const char *path;
  int ret;

  ret = genl_core_require_client_login(info, NULL);
  if (ret) {
    return ret;
  }

  /* 与添加路径共用解析逻辑，确保输入一致性。 */
  ret = genl_core_parse_file_whitelist(info, &path);
  if (ret) {
    pr_warn("%s: failed to parse remove whitelist request: %d\n", __func__,
            ret);
    return ret;
  }

  ret = file_whitelist_remove(path);
  if (ret) {
    pr_warn("%s: file_whitelist_remove failed for \"%s\": %d\n", __func__, path,
            ret);
  }
  return ret;
}

static int genl_core_handle_proc_whitelist_add(struct sk_buff *skb,
                                               struct genl_info *info) {
  int ret;

  ret = genl_core_require_client_login(info, NULL);
  if (ret) {
    return ret;
  }

  // TODO
  // const char *path;
  // int ret;
  // ret = proc_whitelist_add(path);
  // if (ret) {
  //   pr_warn("%s: proc_whitelist_add failed for \"%s\": %d\n", __func__, path,
  //           ret);
  // }
  // return ret;
  return 0;
}

static int genl_core_handle_proc_whitelist_remove(struct sk_buff *skb,
                                                  struct genl_info *info) {
  int ret;

  ret = genl_core_require_client_login(info, NULL);
  if (ret) {
    return ret;
  }

  // TODO
  // const char *path;
  // int ret;
  // ret = proc_whitelist_remove(path);
  // if (ret) {
  //   pr_warn("%s: proc_whitelist_remove failed for \"%s\": %d\n", __func__,
  //   path,
  //           ret);
  // }
  // return ret;
  return 0;
}

/* 注册 genetlink family，并初始化命令/多播配置。 */
int genl_core_init(genl_core_t **core) {
  pr_info("%s\n", __func__);

  if (!core) {
    pr_warn("%s: core is NULL\n", __func__);
    return -EINVAL;
  }

  if (*core) {
    pr_info("%s: genl_core already initialized\n", __func__);
    return 0;
  }

  *core = kmalloc(sizeof(genl_core_t), GFP_KERNEL);
  if (!*core) {
    pr_warn("%s: failed to kmalloc genl_core\n", __func__);
    return -ENOMEM;
  }

  INIT_LIST_HEAD(&(*core)->clients);
  spin_lock_init(&(*core)->clients_lock);

  /* 在栈上准备策略、组和命令的模板配置。 */
  struct nla_policy policy[TCM_GENL_ATTR_MAX] = {
      [TCM_GENL_ATTR_PPID] = {.type = NLA_S32},
      [TCM_GENL_ATTR_PID] = {.type = NLA_S32},
      [TCM_GENL_ATTR_KEY] =
          {
              .type = NLA_NUL_STRING,
              .len = TCM_GENL_ATTR_KEY_MAX_LEN,
          },
      [TCM_GENL_ATTR_PROC_EVENT_TYPE] = {.type = NLA_U8},
      [TCM_GENL_ATTR_FILE_EVENT_TYPE] = {.type = NLA_U8},
      [TCM_GENL_ATTR_FD] = {.type = NLA_S32},
      [TCM_GENL_ATTR_PATH1] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_PATH2] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_FILE_STATS_PID_TABLE_SIZE] = {.type = NLA_U32},
      [TCM_GENL_ATTR_FILE_STATS_PID_ENTRY_COUNT] = {.type = NLA_U32},
      [TCM_GENL_ATTR_FILE_STATS_FILE_ENTRY_COUNT] = {.type = NLA_U32},
      [TCM_GENL_ATTR_FILE_STATS_TOP_PID_COUNT] = {.type = NLA_U32},
      [TCM_GENL_ATTR_FILE_STATS_TOP_PIDS] =
          {
              .type = NLA_BINARY,
              .len = FILE_LISTENER_TOP_PID_LIMIT *
                     sizeof(file_listener_pid_stat_t),
          },
  };
  struct genl_multicast_group mcgrps[TCM_GENL_MCGRP_COUNT] = {
      [TCM_GENL_MCGRP_HOOK] =
          {
              .name = TCM_GENL_MCGRP_HOOK_NAME,
          },
  };
  struct genl_ops ops[TCM_GENL_CMD_OPS_COUNT] = {
      {
          .cmd = TCM_GENL_CMD_LOGIN,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_login,
      },
      {
          .cmd = TCM_GENL_CMD_GET_FILE_STATS,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_get_file_stats,
      },
      {
          .cmd = TCM_GENL_CMD_FILE_WHITELIST_ADD,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_file_whitelist_add,
      },
      {
          .cmd = TCM_GENL_CMD_FILE_WHITELIST_REMOVE,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_file_whitelist_remove,
      },
      {
          .cmd = TCM_GENL_CMD_PROC_WHITELIST_ADD,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_proc_whitelist_add,
      },
      {
          .cmd = TCM_GENL_CMD_PROC_WHITELIST_REMOVE,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_proc_whitelist_remove,
      },
  };

  /* 将模板拷贝到核心结构中，避免直接引用栈内存。 */
  memcpy((*core)->policy, policy, sizeof(policy));
  memcpy((*core)->mcgrps, mcgrps, sizeof(mcgrps));
  memcpy((*core)->ops, ops, sizeof(ops));

  /* 填充 genetlink family 元数据，绑定策略与操作表。 */
  (*core)->family = (struct genl_family){
      .name = TCM_GENL_FAMILY_NAME,
      .version = TCM_GENL_VERSION,
      .maxattr = TCM_GENL_ATTR_MAX,
      .policy = (*core)->policy,
      .module = THIS_MODULE,
      .mcgrps = (*core)->mcgrps,
      .n_mcgrps = TCM_GENL_MCGRP_COUNT,
      .ops = (*core)->ops,
      .n_ops = TCM_GENL_CMD_OPS_COUNT,
  };
  (*core)->file_listener = NULL;

  /* 向内核注册该 family，完成 Netlink 接口初始化。 */
  int ret = genl_register_family(&(*core)->family);
  if (ret) {
    pr_err("%s: genl_register_family failed: %d\n", __func__, ret);
    genl_core_exit(core);
    return ret;
  }

  pr_info("  %s: success, with family .name=%s, .version=%d -> .id=%d\n",
          __func__, (*core)->family.name, (*core)->family.version,
          (*core)->family.id);
  return 0;
}

/* 注销 genetlink family 并释放上下文。 */
void genl_core_exit(genl_core_t **core) {
  if (!core) {
    pr_warn("%s: invalid genl_core\n", __func__);
    return;
  }

  if (!*core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }

  pr_info("%s\n", __func__);

  genl_unregister_family(&(*core)->family);
  genl_core_clients_clear(*core);

  kfree(*core);
  *core = NULL;
}

/* 绑定文件监听器，便于在事件回调中转发到 Netlink。 */
int genl_core_set_file_listener(genl_core_t *core, file_listener_t *listener) {
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
  }

  core->file_listener = listener;
  return 0;
}

/* 将进程事件封装为 Netlink 多播消息。 */
static int genl_core_send_proc_event(genl_core_t *core,
                                     const proc_event_t *event) {
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
  }

  struct sk_buff *skb;
  void *msg_head;

  /* 为进程事件准备 Netlink skb。 */
  skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
  if (!skb) {
    pr_warn("%s: failed to allocate netlink skb\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(skb, 0, 0, &core->family, 0, TCM_GENL_CMD_PROC_EVENT);
  if (!msg_head) {
    pr_warn("%s: genlmsg_put failed\n", __func__);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  /* 按属性编码进程事件类型、PID、PPID，供用户态解码。 */
  if (nla_put_u8(skb, TCM_GENL_ATTR_PROC_EVENT_TYPE, event->type) ||
      nla_put_s32(skb, TCM_GENL_ATTR_PID, event->pid) ||
      nla_put_s32(skb, TCM_GENL_ATTR_PPID, event->ppid)) {
    pr_warn("%s: nla_put failed for proc_event\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  /* 投递多播消息；若当前无订阅者，允许返回 -ESRCH。 */
  int ret =
      genlmsg_multicast(&core->family, skb, 0, TCM_GENL_MCGRP_HOOK, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed for proc_event: %d\n", __func__, ret);
    return ret;
  }

  return 0;
}

/* 将文件操作事件推送到用户态。 */
static int genl_core_send_file_event(genl_core_t *core,
                                     const file_event_t *event) {
  struct sk_buff *skb;
  void *msg_head;
  int ret;
  size_t payload_len;
  size_t path_len;

  if (!core) {
    pr_warn("%s: genl_core is NULL\n", __func__);
    return -EINVAL;
  }

  if (!event) {
    pr_warn("%s: event is NULL\n", __func__);
    return -EINVAL;
  }

  path_len = strnlen(event->path, PATH_MAX - 1) + 1;
  payload_len = NLMSG_HDRLEN + GENL_HDRLEN + nla_total_size(sizeof(s32)) +
                nla_total_size(sizeof(s32)) + nla_total_size(sizeof(u8)) +
                nla_total_size(path_len);

  /* 分配新的 skb 来承载文件事件通知。 */
  skb = genlmsg_new(payload_len, GFP_ATOMIC);
  if (!skb) {
    pr_warn("%s: failed to allocate netlink skb\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(skb, 0, 0, &core->family, 0, TCM_GENL_CMD_FILE_EVENT);
  if (!msg_head) {
    pr_warn("%s: genlmsg_put failed\n", __func__);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  /* 将 PID、FD、操作类型与路径依次写入属性。 */
  if (nla_put_u8(skb, TCM_GENL_ATTR_FILE_EVENT_TYPE, event->type) ||
      nla_put_s32(skb, TCM_GENL_ATTR_FD, event->fd) ||
      nla_put_s32(skb, TCM_GENL_ATTR_PID, event->pid) ||
      nla_put_string(skb, TCM_GENL_ATTR_PATH1, event->path)) {
    pr_warn("%s: nla_put failed for file_event\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  /* 广播给 hook 组订阅方，若无人订阅则忽略 ESRCH。 */
  ret =
      genlmsg_multicast(&core->family, skb, 0, TCM_GENL_MCGRP_HOOK, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed: %d\n", __func__, ret);
    return ret;
  }

  return 0;
}

/* file 监听器回调，通过 Netlink 转发事件。 */
void genl_core_on_file_event(const file_event_t *event, void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }
  genl_core_send_file_event(core, event);
}

/* 进程事件监听器回调，通过 Netlink 转发事件。 */
void genl_core_on_proc_event(const proc_event_t *event, void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }

  genl_core_send_proc_event(core, event);
}
