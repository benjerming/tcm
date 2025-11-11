#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/genetlink.h>
#include <net/netlink.h>

#include "linux/array_size.h"
#include "tcm/api.h"
#include "tcm/listeners/file.h"
#include "tcm/netlink/genl.h"
#include "tcm/whitelist/pid.h"

struct genl_core {
  struct nla_policy policy[TCM_GENL_ATTR_MAX + 1];
  struct genl_multicast_group mcgrps[TCM_GENL_MCGRP_MAX + 1];
  struct genl_ops ops[TCM_GENL_OP_MAX + 1];
  struct genl_family family;
  file_listener_t *file_listener;
};

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
    pid = (pid_t)nla_get_u32(info->attrs[TCM_GENL_ATTR_CLIENT_PID]);
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

  ret = file_listener_get_stats(core->file_listener, &stats);
  if (ret) {
    pr_warn("%s: file_listener_get_stats failed: %d\n", __func__, ret);
    return ret;
  }

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

  struct nla_policy policy[] = {
      [TCM_GENL_ATTR_PARENT_PID] = {.type = NLA_U32},
      [TCM_GENL_ATTR_CHILD_PID] = {.type = NLA_U32},
      [TCM_GENL_ATTR_PARENT_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_CHILD_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_FILE_PID] = {.type = NLA_U32},
      [TCM_GENL_ATTR_FILE_FD] = {.type = NLA_U32},
      [TCM_GENL_ATTR_FILE_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_GENL_ATTR_FILE_OPERATION] = {.type = NLA_U8},
      [TCM_GENL_ATTR_EXIT_PID] = {.type = NLA_U32},
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
      [TCM_GENL_ATTR_CLIENT_PID] = {.type = NLA_U32},
  };
  struct genl_multicast_group mcgrps[] = {
      [TCM_GENL_MCGRP_HOOK] =
          {
              .name = TCM_GENL_MCGRP_HOOK_NAME,
          },
  };
  struct genl_ops ops[] = {
      {
          .cmd = TCM_GENL_OP_REGISTER,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_register,
      },
      {
          .cmd = TCM_GENL_OP_GET_FILE_STATS,
          .policy = (*core)->policy,
          .maxattr = TCM_GENL_ATTR_MAX,
          .doit = genl_core_handle_get_file_stats,
      },
  };

  memcpy((*core)->policy, policy, sizeof(policy));
  memcpy((*core)->mcgrps, mcgrps, sizeof(mcgrps));
  memcpy((*core)->ops, ops, sizeof(ops));

  (*core)->family = (struct genl_family){
      .name = TCM_GENL_FAMILY_NAME,
      .version = TCM_GENL_VERSION,
      .maxattr = TCM_GENL_ATTR_MAX,
      .policy = (*core)->policy,
      .module = THIS_MODULE,
      .mcgrps = (*core)->mcgrps,
      .n_mcgrps = ARRAY_SIZE(mcgrps),
      .ops = (*core)->ops,
      .n_ops = ARRAY_SIZE(ops),
  };
  (*core)->file_listener = NULL;

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

int genl_core_set_file_listener(genl_core_t *core, file_listener_t *listener) {
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
  }

  core->file_listener = listener;
  return 0;
}

static int genl_core_send_fork_ret_event(genl_core_t *core,
                                         const fork_ret_event_t *event) {
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return -EINVAL;
  }

  struct sk_buff *skb;
  void *msg_head;

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

  if (nla_put_u32(skb, TCM_GENL_ATTR_PARENT_PID, event->parent_pid) ||
      nla_put_u32(skb, TCM_GENL_ATTR_CHILD_PID, event->child_pid)) {
    pr_warn("%s: nla_put failed for fork_ret_event\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  int ret =
      genlmsg_multicast(&core->family, skb, 0, TCM_GENL_MCGRP_HOOK, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed for fork_ret_event: %d\n", __func__,
            ret);
    return ret;
  }

  return 0;
}

static int genl_core_send_file_event(genl_core_t *core,
                                     const file_event_t *event) {
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

  skb = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
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

  if (nla_put_u32(skb, TCM_GENL_ATTR_FILE_PID, event->pid) ||
      nla_put_u32(skb, TCM_GENL_ATTR_FILE_FD, event->fd) ||
      nla_put_u8(skb, TCM_GENL_ATTR_FILE_OPERATION, (u8)event->operation) ||
      nla_put_string(skb, TCM_GENL_ATTR_FILE_PATH, event->path)) {
    pr_warn("%s: nla_put failed for file_event\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  ret =
      genlmsg_multicast(&core->family, skb, 0, TCM_GENL_MCGRP_HOOK, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed: %d\n", __func__, ret);
    return ret;
  }

  return 0;
}

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

  if (nla_put_u32(skb, TCM_GENL_ATTR_EXIT_PID, event->pid) ||
      nla_put_s32(skb, TCM_GENL_ATTR_EXIT_CODE, event->code)) {
    pr_warn("%s: nla_put failed for exit_event\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  ret =
      genlmsg_multicast(&core->family, skb, 0, TCM_GENL_MCGRP_HOOK, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed for exit_event: %d\n", __func__, ret);
    return ret;
  }

  return 0;
}

void genl_core_on_exit_event(const exit_event_t *event, void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }

  genl_core_send_exit_event(core, event);
}

void genl_core_on_file_event(const file_event_t *event, void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }
  genl_core_send_file_event(core, event);
}

void genl_core_on_fork_ret_event(const fork_ret_event_t *event,
                                 void *user_data) {
  genl_core_t *core = (genl_core_t *)user_data;
  if (!core) {
    pr_warn("%s: genl_core not initialized\n", __func__);
    return;
  }

  genl_core_send_fork_ret_event(core, event);
}
