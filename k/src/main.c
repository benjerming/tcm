#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "tcm/listeners/exit.h"
#include "tcm/listeners/file.h"
#include "tcm/listeners/forkret.h"
#include "tcm/netlink/genl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TCM-Team");
MODULE_DESCRIPTION("TCM-Team Module");
MODULE_VERSION("1.0.0");

static exit_listener_t *s_exit_listener = NULL;
static file_listener_t *s_file_listener = NULL;
static fork_ret_listener_t *s_fork_ret_listener = NULL;
static genl_core_t *s_genl_core = NULL;

static int tcm_init_impl(void) {
  int ret;
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

static void tcm_exit_impl(void) {
  if (s_genl_core) {
    genl_core_set_file_listener(s_genl_core, NULL);
  }
  exit_listener_exit(&s_exit_listener);
  file_listener_exit(&s_file_listener);
  fork_ret_listener_exit(&s_fork_ret_listener);
  genl_core_exit(&s_genl_core);
}

static int __init tcm_init(void) {
  int ret;
  pr_info("%s\n", __func__);
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
  tcm_exit_impl();
}

module_init(tcm_init);
module_exit(tcm_exit);
