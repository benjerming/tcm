#ifndef TCM_KPROBE_H
#define TCM_KPROBE_H

#include <linux/kprobes.h>
#include <linux/types.h>

struct tcm_kprobe_handle;
struct tcm_kretprobe_handle;

/* kprobe 配置结构体，封装预处理/后处理回调及用户数据指针。 */
struct tcm_kprobe_config {
  kprobe_pre_handler_t pre_handler;
  kprobe_post_handler_t post_handler;
  void *user_data;
};

/* kretprobe 配置结构体，关注函数返回场景。 */
struct tcm_kretprobe_config {
  kretprobe_handler_t handler;
  kretprobe_handler_t entry_handler;
  int maxactive;
  size_t data_size;
  void *user_data;
};

/* 枚举所有支持的 kprobe 目标，保持与目标表一一对应。 */
enum tcm_kprobe_target {
  TCM_KPROBE_TARGET_FILE_WRITE = 0,
  TCM_KPROBE_TARGET_FILE_CLOSE,
  TCM_KPROBE_TARGET_DO_EXIT,
  TCM_KPROBE_TARGET_COUNT,
};

/* 枚举所有支持的 kretprobe 目标。 */
enum tcm_kretprobe_target {
  TCM_KRETPROBE_TARGET_FILE_OPEN = 0,
  TCM_KRETPROBE_TARGET_FORK_CLONE,
  TCM_KRETPROBE_TARGET_COUNT,
};

int tcm_kprobe_register(enum tcm_kprobe_target target,
                        const struct tcm_kprobe_config *config,
                        struct tcm_kprobe_handle **handle);
void tcm_kprobe_unregister(struct tcm_kprobe_handle **handle);

void *tcm_kprobe_get_user_data(const struct kprobe *kp);

int tcm_kretprobe_register(enum tcm_kretprobe_target target,
                           const struct tcm_kretprobe_config *config,
                           struct tcm_kretprobe_handle **handle);
void tcm_kretprobe_unregister(struct tcm_kretprobe_handle **handle);
void *tcm_kretprobe_get_user_data(const struct kretprobe *krp);

#endif /* TCM_KPROBE_H */
