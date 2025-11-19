#ifndef TCM_LOGIN_H
#define TCM_LOGIN_H

#include "tcm/api.h"

typedef struct login_manager login_manager_t;

int login_manager_init(login_manager_t **manager);
void login_manager_exit(login_manager_t **manager);
int login_manager_login(login_manager_t *manager, pid_t pid,
                        const login_op_t *op);
int login_manager_logout(login_manager_t *manager, pid_t pid);
bool login_manager_contains(login_manager_t *manager, pid_t pid);

#endif /* TCM_LOGIN_H */
