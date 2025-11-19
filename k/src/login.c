#include "tcm/login.h"
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

typedef struct {
  struct list_head node;
  pid_t pid;
} client_node_t;

struct login_manager {
  struct list_head clients;
  spinlock_t clients_lock;
};

int login_manager_init(login_manager_t **manager) {
  *manager = kmalloc(sizeof(login_manager_t), GFP_KERNEL);
  if (!*manager) {
    return -ENOMEM;
  }
  INIT_LIST_HEAD(&(*manager)->clients);
  spin_lock_init(&(*manager)->clients_lock);
  return 0;
}

static void login_manager_clients_clear(login_manager_t *manager) {
  client_node_t *client, *tmp;
  unsigned long flags;
  if (!manager) {
    return;
  }
  spin_lock_irqsave(&manager->clients_lock, flags);
  list_for_each_entry_safe(client, tmp, &manager->clients, node) {
    list_del(&client->node);
    kfree(client);
  }
  spin_unlock_irqrestore(&manager->clients_lock, flags);
}

void login_manager_exit(login_manager_t **manager) {
  if (!manager || !*manager) {
    return;
  }
  login_manager_clients_clear(*manager);
  kfree(*manager);
  *manager = NULL;
}

static bool login_manager_clients_contains_locked(login_manager_t *manager,
                                                  pid_t pid) {
  client_node_t *client;
  list_for_each_entry(client, &manager->clients, node) {
    if (client->pid == pid) {
      return true;
    }
  }
  return false;
}

static int login_manager_clients_add(login_manager_t *manager, pid_t pid) {
  client_node_t *client;
  unsigned long flags;
  if (!manager) {
    return -EINVAL;
  }
  spin_lock_irqsave(&manager->clients_lock, flags);
  if (login_manager_clients_contains_locked(manager, pid)) {
    spin_unlock_irqrestore(&manager->clients_lock, flags);
    return -EEXIST;
  }
  client = kmalloc(sizeof(client_node_t), GFP_KERNEL);
  if (!client) {
    spin_unlock_irqrestore(&manager->clients_lock, flags);
    return -ENOMEM;
  }
  client->pid = pid;
  list_add(&client->node, &manager->clients);
  spin_unlock_irqrestore(&manager->clients_lock, flags);
  return 0;
}

static int login_manager_clients_remove(login_manager_t *manager, pid_t pid) {
  client_node_t *client;
  unsigned long flags;
  if (!manager) {
    return -EINVAL;
  }
  spin_lock_irqsave(&manager->clients_lock, flags);
  if (!login_manager_clients_contains_locked(manager, pid)) {
    spin_unlock_irqrestore(&manager->clients_lock, flags);
    return -ENOENT;
  }
  client = list_first_entry(&manager->clients, client_node_t, node);
  list_del(&client->node);
  kfree(client);
  spin_unlock_irqrestore(&manager->clients_lock, flags);
  return 0;
}

int login_manager_login(login_manager_t *manager, pid_t pid,
                        const login_op_t *op) {
  int ret;
  if (!manager || !op) {
    return -EINVAL;
  }
  if (strcmp(op->key, "1234567890") != 0) {
    return -EINVAL;
  }

  ret = login_manager_clients_add(manager, pid);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

int login_manager_logout(login_manager_t *manager, pid_t pid) {
  int ret;
  if (!manager) {
    return -EINVAL;
  }
  ret = login_manager_clients_remove(manager, pid);
  if (ret != 0) {
    return ret;
  }
  return 0;
}

bool login_manager_contains(login_manager_t *manager, pid_t pid) {
  unsigned long flags;
  bool found;
  if (!manager) {
    return false;
  }
  spin_lock_irqsave(&manager->clients_lock, flags);
  found = login_manager_clients_contains_locked(manager, pid);
  spin_unlock_irqrestore(&manager->clients_lock, flags);

  return found;
}
