#ifndef _RAZOR_INTERNAL_H_
#define _RAZOR_INTERNAL_H_

#define ALIGN(value, base) (((value) + (base - 1)) & ~((base) - 1))

/* Utility functions */

int razor_create_dir(const char *root, const char *path);
int razor_write(int fd, const void *data, size_t size);

#endif /* _RAZOR_INTERNAL_H_ */
