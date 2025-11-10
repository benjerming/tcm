#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/genetlink.h>

#include "tcm/api.h"
#include "tcm/netlink/genl.h"

struct genl_core {
  struct nla_policy policy[TCM_ATTR_MAX + 1];
  struct genl_multicast_group mcgrps[TCM_MCGRP_MAX + 1];
  struct genl_family family;
};

int init_genl_core(genl_core_t **gc) {
  pr_info("%s\n", __func__);

  if (!gc) {
    pr_warn("%s: **genl_core is NULL\n", __func__);
    return -EINVAL;
  }

  if (*gc) {
    pr_warn("%s: genl_core is already initialized\n", __func__);
    return -EINVAL;
  }

  *gc = kmalloc(sizeof(genl_core_t), GFP_KERNEL);
  if (!*gc) {
    pr_warn("%s: genl_core is NULL\n", __func__);
    return -ENOMEM;
  }

  struct nla_policy policy[] = {
      [TCM_ATTR_PARENT_PID] = {.type = NLA_U32},
      [TCM_ATTR_CHILD_PID] = {.type = NLA_U32},
      [TCM_ATTR_PARENT_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_ATTR_CHILD_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_ATTR_FILE_PID] = {.type = NLA_U32},
      [TCM_ATTR_FILE_FD] = {.type = NLA_U32},
      [TCM_ATTR_FILE_PATH] = {.type = NLA_NUL_STRING, .len = PATH_MAX},
      [TCM_ATTR_FILE_OPERATION] = {.type = NLA_U8},
      [TCM_ATTR_FILE_BYTES] = {.type = NLA_U64},
  };
  struct genl_multicast_group mcgrps[] = {
      [TCM_MCGRP] =
          {
              .name = TCM_GENL_MCGRP_NAME,
          },
  };
  memcpy((*gc)->policy, policy, sizeof(policy));
  memcpy((*gc)->mcgrps, mcgrps, sizeof(mcgrps));

  (*gc)->family = (struct genl_family){
      .name = TCM_GENL_FAMILY_NAME,
      .version = TCM_GENL_VERSION,
      .maxattr = TCM_ATTR_MAX,
      .policy = (*gc)->policy,
      .module = THIS_MODULE,
      .mcgrps = (*gc)->mcgrps,
      .n_mcgrps = ARRAY_SIZE((*gc)->mcgrps),
  };

  int ret = genl_register_family(&(*gc)->family);
  if (ret) {
    pr_err("%s: genl_register_family failed: %d\n", __func__, ret);
    kfree(*gc);
    *gc = NULL;
    return ret;
  }

  pr_info("  %s: success, with family .name=%s, .version=%d -> .id=%d\n",
          __func__, (*gc)->family.name, (*gc)->family.version,
          (*gc)->family.id);
  return 0;
}

void free_genl_core(genl_core_t **gc) {
  if (!gc) {
    pr_warn("%s: genl_core invalid pointer\n", __func__);
    return;
  }

  if (!*gc) {
    pr_warn("%s: genl_core already freed\n", __func__);
    return;
  }

  pr_info("%s\n", __func__);

  genl_unregister_family(&(*gc)->family);

  kfree(*gc);
  *gc = NULL;
}

int genl_core_send_fork_ret_event(genl_core_t *gc,
                                  const fork_ret_event_t *event) {
  if (!gc) {
    pr_warn("%s: genl_core is NULL\n", __func__);
    return -EINVAL;
  }

  struct sk_buff *skb;
  void *msg_head;

  skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
  if (!skb) {
    pr_warn("%s: failed to allocate netlink skb\n", __func__);
    return -ENOMEM;
  }

  msg_head = genlmsg_put(skb, 0, 0, &gc->family, 0, TCM_CMD_FORK_RET_EVENT);
  if (!msg_head) {
    pr_warn("%s: genlmsg_put failed\n", __func__);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  if (nla_put_u32(skb, TCM_ATTR_PARENT_PID, event->parent_pid) ||
      nla_put_u32(skb, TCM_ATTR_CHILD_PID, event->child_pid)) {
    pr_warn("%s: nla_put failed\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  int ret = genlmsg_multicast(&gc->family, skb, 0, TCM_MCGRP, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed: %d\n", __func__, ret);
    return ret;
  }

  return 0;
}

int genl_core_send_file_event(genl_core_t *gc, const file_event_t *event) {
  struct sk_buff *skb;
  void *msg_head;
  int ret;

  if (!gc) {
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

  msg_head = genlmsg_put(skb, 0, 0, &gc->family, 0, TCM_CMD_FILE_EVENT);
  if (!msg_head) {
    pr_warn("%s: genlmsg_put failed\n", __func__);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  if (nla_put_u32(skb, TCM_ATTR_FILE_PID, event->pid) ||
      nla_put_u32(skb, TCM_ATTR_FILE_FD, event->fd) ||
      nla_put_u8(skb, TCM_ATTR_FILE_OPERATION, (u8)event->operation) ||
      nla_put_string(skb, TCM_ATTR_FILE_PATH, event->path) ||
      nla_put_u64_64bit(skb, TCM_ATTR_FILE_BYTES, event->bytes,
                        TCM_ATTR_UNSPEC)) {
    pr_warn("%s: nla_put failed\n", __func__);
    genlmsg_cancel(skb, msg_head);
    nlmsg_free(skb);
    return -EMSGSIZE;
  }

  genlmsg_end(skb, msg_head);

  ret = genlmsg_multicast(&gc->family, skb, 0, TCM_MCGRP, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn("%s: genlmsg_multicast failed: %d\n", __func__, ret);
    return ret;
  }

  return 0;
}
