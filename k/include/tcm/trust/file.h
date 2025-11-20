#ifndef TCM_TRUST_FILE_H
#define TCM_TRUST_FILE_H

#include <linux/types.h>

int trust_file_init(void);
void trust_file_exit(void);
int trust_file_add(const char *path);
int trust_file_remove(const char *path);
bool trust_file_contains(const char *path);

#endif /* TCM_TRUST_FILE_H */
