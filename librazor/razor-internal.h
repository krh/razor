#ifndef _RAZOR_INTERNAL_H_
#define _RAZOR_INTERNAL_H_

#define ALIGN(value, base) (((value) + (base - 1)) & ~((base) - 1))

/* Utility functions */

int razor_create_dir(const char *root, const char *path);
int razor_write(int fd, const void *data, size_t size);


typedef int (*razor_compare_with_data_func_t)(const void *p1,
					      const void *p,
					      void *data);
uint32_t *
razor_qsort_with_data(void *base, size_t nelem, size_t size,
		      razor_compare_with_data_func_t compare, void *data);

#endif /* _RAZOR_INTERNAL_H_ */
