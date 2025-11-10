#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "tcm/common.h"
#include "tcm/listeners/fork.h"
#include "tcm/listeners/file.h"
#include "tcm/netlink/genl.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TCM-Team");
MODULE_DESCRIPTION("TCM-Team Module");
MODULE_VERSION("1.0.0");

MAYBE_UNUSED static fork_listener_t *fork_listener;
static fork_ret_listener_t *forkret_listener;
static file_listener_t *file_listener;
static genl_core_t *genl_core;

MAYBE_UNUSED static void fork_event_callback(const fork_event_t *event,
                                             void *user_data) {
  genl_core_t *gc = (genl_core_t *)user_data;
  genl_core_send_fork_event(gc, event);
}

static void file_event_callback(const file_event_t *event, void *user_data) {
  genl_core_t *gc = (genl_core_t *)user_data;
  genl_core_send_file_event(gc, event);
}

static void fork_event_ret_callback(const fork_ret_event_t *event,
                                    void *user_data) {
  genl_core_t *gc = (genl_core_t *)user_data;
  genl_core_send_fork_ret_event(gc, event);
}

static int tcm_init_impl(void) {
  int ret;
  ret = init_genl_core(&genl_core);
  if (ret) {
    return ret;
  }

  // ret = init_fork_listener(&fork_listener, fork_event_callback, genl_core);
  // if (ret) {
  //   return ret;
  // }

  ret = init_file_listener(&file_listener, file_event_callback, genl_core);
  if (ret) {
    return ret;
  }

  ret = init_fork_ret_listener(&forkret_listener, fork_event_ret_callback,
                               genl_core);
  if (ret) {
    return ret;
  }

  return 0;
}

static void tcm_exit_impl(void) {
  // free_fork_listener(&fork_listener);
  free_fork_ret_listener(&forkret_listener);
  free_file_listener(&file_listener);
  free_genl_core(&genl_core);
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
