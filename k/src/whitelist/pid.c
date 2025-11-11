#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/threads.h>

#include "tcm/whitelist/pid.h"

#define PID_WHITELIST_MAX 128
#define PID_WHITELIST_PARAM_LEN 512

static DEFINE_RWLOCK(whitelist_pid_lock);
static pid_t pid_whitelist[PID_WHITELIST_MAX];
static size_t pid_whitelist_count;
static char pid_whitelist_raw[PID_WHITELIST_PARAM_LEN];

static void format_pid_whitelist_string(const pid_t *pids, size_t count,
                                        char *out, size_t outlen) {
  size_t offset = 0;
  size_t i;

  if (!out || outlen == 0) {
    return;
  }

  out[0] = '\0';

  for (i = 0; i < count && offset < outlen; ++i) {
    int written = scnprintf(out + offset, outlen - offset, "%s%d",
                            (i == 0) ? "" : ",", pids[i]);
    if (written <= 0) {
      break;
    }
    offset += written;
    if (offset >= outlen) {
      out[outlen - 1] = '\0';
      break;
    }
  }
}

static int parse_pid_list(char *input, pid_t *out, size_t max, size_t *count) {
  char *cursor;
  char *token;
  size_t idx = 0;

  if (!out || !count || !input) {
    return -EINVAL;
  }

  cursor = input;

  while ((token = strsep(&cursor, ", \t")) != NULL) {
    long value;
    int ret;
    bool exists = false;
    size_t i;

    if (*token == '\0') {
      continue;
    }

    ret = kstrtol(token, 10, &value);
    if (ret) {
      return ret;
    }

    if (value < 0 || value > PID_MAX_LIMIT) {
      return -ERANGE;
    }

    for (i = 0; i < idx; ++i) {
      if (out[i] == (pid_t)value) {
        exists = true;
        break;
      }
    }

    if (exists) {
      continue;
    }

    if (idx >= max) {
      return -E2BIG;
    }

    out[idx++] = (pid_t)value;
  }

  *count = idx;
  return 0;
}

int pid_whitelist_add(pid_t pid) {
  bool added = false;
  size_t i;
  int ret = 0;

  if (pid <= 0 || pid > PID_MAX_LIMIT) {
    return -EINVAL;
  }

  write_lock(&whitelist_pid_lock);

  for (i = 0; i < pid_whitelist_count; ++i) {
    if (pid_whitelist[i] == pid) {
      ret = -EEXIST;
      goto out_unlock;
    }
  }

  if (pid_whitelist_count >= PID_WHITELIST_MAX) {
    ret = -E2BIG;
    goto out_unlock;
  }

  pid_whitelist[pid_whitelist_count++] = pid;
  if (pid_whitelist_count < PID_WHITELIST_MAX) {
    pid_whitelist[pid_whitelist_count] = 0;
  }
  format_pid_whitelist_string(pid_whitelist, pid_whitelist_count,
                              pid_whitelist_raw, sizeof(pid_whitelist_raw));
  added = true;

out_unlock:
  write_unlock(&whitelist_pid_lock);

  if (added) {
    pr_info("pid_whitelist: added pid=%d (count=%zu)\n", pid,
            pid_whitelist_count);
  }

  return ret;
}

bool pid_whitelist_contains(pid_t pid) {
  size_t i;
  bool found = false;

  read_lock(&whitelist_pid_lock);
  for (i = 0; i < pid_whitelist_count; ++i) {
    if (pid_whitelist[i] == pid) {
      found = true;
      break;
    }
  }
  read_unlock(&whitelist_pid_lock);

  return found;
}

static int pid_whitelist_param_set(const char *val,
                                   const struct kernel_param *kp) {
  char buf[PID_WHITELIST_PARAM_LEN];
  char *trimmed;
  pid_t parsed[PID_WHITELIST_MAX];
  size_t count = 0;
  int ret;
  bool cleared;

  if (!val) {
    return -EINVAL;
  }

  strscpy(buf, val, sizeof(buf));
  trimmed = strim(buf);

  ret = parse_pid_list(trimmed, parsed, PID_WHITELIST_MAX, &count);
  if (ret) {
    return ret;
  }

  write_lock(&whitelist_pid_lock);
  pid_whitelist_count = count;
  if (count > 0) {
    memcpy(pid_whitelist, parsed, sizeof(parsed[0]) * count);
  }
  if (count < PID_WHITELIST_MAX) {
    memset(pid_whitelist + count, 0,
           sizeof(pid_whitelist[0]) * (PID_WHITELIST_MAX - count));
  }
  format_pid_whitelist_string(pid_whitelist, count, pid_whitelist_raw,
                              sizeof(pid_whitelist_raw));
  write_unlock(&whitelist_pid_lock);

  cleared = (count == 0);
  if (cleared) {
    pr_info("pid_whitelist: cleared\n");
  } else {
    pr_info("pid_whitelist: updated (%zu entries)\n", count);
  }

  return 0;
}

static int pid_whitelist_param_get(char *buffer,
                                   const struct kernel_param *kp) {
  int len;

  if (!buffer) {
    return -EINVAL;
  }

  read_lock(&whitelist_pid_lock);
  len = scnprintf(buffer, PAGE_SIZE, "%s\n", pid_whitelist_raw);
  read_unlock(&whitelist_pid_lock);

  return len;
}

static const struct kernel_param_ops pid_whitelist_ops = {
    .set = pid_whitelist_param_set,
    .get = pid_whitelist_param_get,
};

module_param_cb(pid_whitelist, &pid_whitelist_ops, NULL, 0644);
MODULE_PARM_DESC(pid_whitelist, "Comma-separated list of process IDs ignored "
                                "by the event listeners.");
