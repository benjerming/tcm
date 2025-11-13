#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "tcm/api.h"
#include "tcm/listeners/file.h"
#include "tcm/netlink/genl.h"
#include "tcm/whitelist/file.h"
#include "tcm/whitelist/pid.h"

/*
 * 通用 Netlink 核心：
 *  - 负责注册 genetlink family、命令与多播组
 *  - 将来自监听器的事件转发给用户态
 *  - 提供白名单与统计信息的控制接口
 */

/* genetlink 核心上下文，封装 family、ops、监听器等状态。 */
struct genl_core {
  struct nla_policy policy[TCM_GENL_ATTR_MAX];
  struct genl_multicast_group mcgrps[TCM_GENL_MCGRP_COUNT];
  struct genl_ops ops[TCM_GENL_CMD_OPS_COUNT];
  struct genl_family family;
  file_listener_t *file_listener;
};

/* 处理客户端注册请求，将调用方 PID 加入白名单。 */
static int genl_core_handle_register(struct sk_buff *skb,
                                     struct genl_info *info) {
  genl_core_t *core;
  pid_t pid;
  int ret;

  if (!info) {
    pr_warn("%s: invalid genl_info\n", __func__);
    return -EINVAL;
  }

  core = container_of(info->family, genl_core_t, family);
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
  }

  if (info->attrs[TCM_GENL_ATTR_CLIENT_PID]) {
    pid = (pid_t)nla_get_s32(info->attrs[TCM_GENL_ATTR_CLIENT_PID]);
  } else {
    pid = (pid_t)info->snd_portid;
  }

  if (pid <= 0) {
    pr_warn("%s: invalid pid (%d)\n", __func__, pid);
    return -EINVAL;
  }

  ret = pid_whitelist_add(pid);
  if (ret == -EEXIST) {
    ret = 0;
  }
  if (ret) {
    pr_warn("%s: pid_whitelist_add failed for pid=%d: %d\n", __func__, pid,
            ret);
    return ret;
  }

  pr_info("%s: registered client pid=%d\n", __func__, pid);
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

  if (!info) {
    pr_warn("%s: invalid genl_info\n", __func__);
    return -EINVAL;
  }

  core = container_of(info->family, genl_core_t, family);
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
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

  if (!info->attrs[TCM_GENL_ATTR_FILE_WHITELIST_PATH]) {
    pr_warn("%s: missing FILE_WHITELIST_PATH attribute\n", __func__);
    return -EINVAL;
  }

  *path = nla_data(info->attrs[TCM_GENL_ATTR_FILE_WHITELIST_PATH]);
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

  /* 在栈上准备策略、组和命令的模板配置。 */
  struct nla_policy policy[TCM_GENL_ATTR_MAX] = {
      [TCM_GENL_ATTR_PARENT_PID] = {.type = NLA_S32},
      [TCM_GENL_ATTR_CHILD_PID] = {.type = NLA_S32},
      [TCM_GENL_ATTR_PARENT_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_CHILD_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_FILE_PID] = {.type = NLA_S32},
      [TCM_GENL_ATTR_FILE_FD] = {.type = NLA_S32},
      [TCM_GENL_ATTR_FILE_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_FILE_OPERATION] = {.type = NLA_U8},
      [TCM_GENL_ATTR_EXIT_PID] = {.type = NLA_S32},
      [TCM_GENL_ATTR_EXIT_CODE] = {.type = NLA_S32},
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
      [TCM_GENL_ATTR_CLIENT_PID] = {.type = NLA_S32},
      [TCM_GENL_ATTR_FILE_WHITELIST_PATH] =
          {
              .type = NLA_NUL_STRING,
              .len = PATH_MAX,
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
          .cmd = TCM_GENL_CMD_REGISTER,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_register,
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

/* 将 fork 返回事件封装为 Netlink 多播消息。 */
static int genl_core_send_fork_ret_event(genl_core_t *core,
                                         const fork_ret_event_msg_t *event) {
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
  }

  struct sk_buff *skb;
  void *msg_head;

  /* 为 fork 返回事件准备 Netlink skb。 */
  skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
  if (!skb) {
    pr_warn("%s: failed to allocate netlink skb\n", __func__);
    return -ENOMEM;
  }

  msg_head =
      genlmsg_put(skb, 0, 0, &core->family, 0, TCM_GENL_CMD_FORK_RET_EVENT);
  if (!msg_head) {
    pr_warn("%s: genlmsg_put failed\n", __func__);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  /* 按属性编码父/子进程 PID，供用户态解码。 */
  if (nla_put_s32(skb, TCM_GENL_ATTR_PARENT_PID, event->parent_pid) ||
      nla_put_s32(skb, TCM_GENL_ATTR_CHILD_PID, event->child_pid)) {
    pr_warn("%s: nla_put failed for fork_ret_event\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  /* 投递多播消息；若当前无订阅者，允许返回 -ESRCH。 */
  int ret =
      genlmsg_multicast(&core->family, skb, 0, TCM_GENL_MCGRP_HOOK, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed for fork_ret_event: %d\n", __func__,
            ret);
    return ret;
  }

  return 0;
}

/* 将文件操作事件推送到用户态。 */
static int genl_core_send_file_event(genl_core_t *core,
                                     const file_event_msg_t *event) {
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
  if (nla_put_s32(skb, TCM_GENL_ATTR_FILE_PID, event->pid) ||
      nla_put_s32(skb, TCM_GENL_ATTR_FILE_FD, event->fd) ||
      nla_put_u8(skb, TCM_GENL_ATTR_FILE_OPERATION, (u8)event->operation) ||
      nla_put_string(skb, TCM_GENL_ATTR_FILE_PATH, event->path)) {
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

/* 将进程退出事件推送到用户态。 */
static int genl_core_send_exit_event(genl_core_t *core,
                                     const exit_event_t *event) {
  struct sk_buff *skb;
  void *msg_head;
  int ret;

  if (!core) {
    pr_warn("%s: genl_core is NULL\n", __func__);
    return -EINVAL;
  }

  if (!event) {
    pr_warn("%s: event is NULL\n", __func__);
    return -EINVAL;
  }

  /* 为进程退出事件创建 skb，并填充相应属性。 */
  skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
  if (!skb) {
    pr_warn("%s: failed to allocate netlink skb\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(skb, 0, 0, &core->family, 0, TCM_GENL_CMD_EXIT_EVENT);
  if (!msg_head) {
    pr_warn("%s: genlmsg_put failed\n", __func__);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  /* 写入退出 PID 与退出码，便于用户态做清理。 */
  if (nla_put_s32(skb, TCM_GENL_ATTR_EXIT_PID, event->pid) ||
      nla_put_s32(skb, TCM_GENL_ATTR_EXIT_CODE, event->code)) {
    pr_warn("%s: nla_put failed for exit_event\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  /* 投递到多播组；没有订阅者时同样忽略 ESRCH。 */
  ret =
      genlmsg_multicast(&core->family, skb, 0, TCM_GENL_MCGRP_HOOK, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed for exit_event: %d\n", __func__, ret);
    return ret;
  }

  return 0;
}

/* exit 监听器回调，通过 Netlink 转发事件。 */
void genl_core_on_exit_event(const exit_event_t *event, void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }

  genl_core_send_exit_event(core, event);
}

/* file 监听器回调，通过 Netlink 转发事件。 */
void genl_core_on_file_event(const file_event_msg_t *event, void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }
  genl_core_send_file_event(core, event);
}

/* fork 返回监听器回调，通过 Netlink 转发事件。 */
void genl_core_on_fork_ret_event(const fork_ret_event_msg_t *event,
                                 void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }

  genl_core_send_fork_ret_event(core, event);
}
