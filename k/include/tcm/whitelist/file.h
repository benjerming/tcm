#ifndef TCM_WHITELIST_FILE_H
#define TCM_WHITELIST_FILE_H

#include <linux/types.h>

int file_whitelist_init(void);
void file_whitelist_exit(void);
int file_whitelist_add(const char *path);
int file_whitelist_remove(const char *path);
bool file_whitelist_contains(const char *path);

#endif /* TCM_WHITELIST_FILE_H */
