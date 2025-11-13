#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>

/*
 * 模块主入口，负责协调各类监听器与 Netlink 通道的生命周期。
 * 该文件中仅保留最小化的初始化与清理流程，方便在内核态快速定位问题。
 */

#include "tcm/listeners/exit.h"
#include "tcm/listeners/file.h"
#include "tcm/listeners/forkret.h"
#include "tcm/netlink/genl.h"
#include "tcm/whitelist/file.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TCM-Team");
MODULE_DESCRIPTION("TCM-Team Module");
MODULE_VERSION("1.0.0");

/* 模块内部持有的监听器与通用 netlink 核心句柄，模块卸载时按需释放。 */
static exit_listener_t *s_exit_listener = NULL;
static file_listener_t *s_file_listener = NULL;
static fork_ret_listener_t *s_fork_ret_listener = NULL;
static genl_core_t *s_genl_core = NULL;

/* 通过 module_param_cb 导出 file_listener 的实时统计信息。 */
static int file_listener_stats_param_set(const char *val,
                                         const struct kernel_param *kp) {
  return -EPERM;
}

static int file_listener_stats_param_get(char *buffer,
                                         const struct kernel_param *kp) {
  file_listener_stats_t stats;
  int len = 0;
  u32 i;

  if (!buffer) {
    return -EINVAL;
  }

  if (!s_file_listener) {
    return scnprintf(buffer, PAGE_SIZE, "<inactive>\n");
  }

  if (file_listener_get_stats(s_file_listener, &stats)) {
    return scnprintf(buffer, PAGE_SIZE, "<error>\n");
  }

  len += scnprintf(buffer + len, PAGE_SIZE - len,
                   "pid_table_size=%u pid_entries=%u file_entries=%u\n",
                   stats.pid_table_size, stats.pid_entry_count,
                   stats.file_entry_count);

  if (stats.top_pid_count == 0) {
    len += scnprintf(buffer + len, PAGE_SIZE - len,
                     "(no active processes)\n");
    return len;
  }

  for (i = 0; i < stats.top_pid_count && len < PAGE_SIZE; ++i) {
    len += scnprintf(buffer + len, PAGE_SIZE - len,
                     "top[%u]: pid=%d file_count=%u\n", i,
                     stats.top_pids[i].pid, stats.top_pids[i].file_count);
  }

  return len;
}

static const struct kernel_param_ops file_listener_stats_param_ops = {
    .set = file_listener_stats_param_set,
    .get = file_listener_stats_param_get,
};

module_param_cb(file_listener_stats, &file_listener_stats_param_ops, NULL,
                0444);

/* 执行实际的初始化逻辑，按依赖顺序创建各组件。 */
static int tcm_init_impl(void) {
  int ret;
  ret = file_whitelist_init();
  if (ret) {
    return ret;
  }

  ret = genl_core_init(&s_genl_core);
  if (ret) {
    return ret;
  }

  ret = file_listener_init(&s_file_listener, genl_core_on_file_event,
                           s_genl_core);
  if (ret) {
    return ret;
  }
  ret = genl_core_set_file_listener(s_genl_core, s_file_listener);
  if (ret) {
    return ret;
  }

  ret = exit_listener_init(&s_exit_listener, genl_core_on_exit_event,
                           s_genl_core);
  if (ret) {
    return ret;
  }

  ret = fork_ret_listener_init(&s_fork_ret_listener,
                               genl_core_on_fork_ret_event, s_genl_core);
  if (ret) {
    return ret;
  }

  return 0;
}

/* 对初始化失败或模块卸载场景执行有序清理，确保引用全部释放。 */
static void tcm_exit_impl(void) {
  if (s_genl_core) {
    genl_core_set_file_listener(s_genl_core, NULL);
  }
  exit_listener_exit(&s_exit_listener);
  file_listener_exit(&s_file_listener);
  fork_ret_listener_exit(&s_fork_ret_listener);
  genl_core_exit(&s_genl_core);
  file_whitelist_exit();
}

static int __init tcm_init(void) {
  int ret;
  pr_info("%s\n", __func__);
  /* 记录初始化开始，并在失败时主动回滚已经完成的步骤。 */
  ret = tcm_init_impl();
  if (ret) {
    pr_err("%s: init failed: %d\n", __func__, ret);
    tcm_exit_impl();
    return ret;
  }

  pr_info("  %s: success\n", __func__);
  return 0;
}

static void __exit tcm_exit(void) {
  pr_info("%s\n", __func__);
  /* 模块退出时仅需调用统一的清理入口。 */
  tcm_exit_impl();
}

module_init(tcm_init);
module_exit(tcm_exit);
