#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "razor-internal.h"

int
razor_create_dir(const char *root, const char *path)
{
	char buffer[PATH_MAX], *p;
	const char *slash, *next;
	struct stat buf;

	/* Create all sub-directories in dir and then create name. We
	 * know root exists and is a dir, root does not end in a '/',
	 * and path has a leading '/'. */

	strcpy(buffer, root);
	p = buffer + strlen(buffer);
	slash = path;
	for (slash = path; *slash != '\0'; slash = next) {
		next = strchr(slash + 1, '/');
		if (next == NULL)
			next = slash + strlen(slash);

		memcpy(p, slash, next - slash);
		p += next - slash;
		*p = '\0';

		if (stat(buffer, &buf) == 0) {
			if (!S_ISDIR(buf.st_mode)) {
				fprintf(stderr,
					"%s exists but is not a directory\n",
					buffer);
				return -1;
			}
		} else if (mkdir(buffer, 0777) < 0) {
			fprintf(stderr, "failed to make directory %s: %m\n",
				buffer);
			return -1;
		}

		/* FIXME: What to do about permissions for dirs we
		 * have to create but are not in the cpio archive? */
	}

	return 0;
}

int
razor_write(int fd, const void *data, size_t size)
{
	size_t rest;
	ssize_t written;
	const unsigned char *p;

	rest = size;
	p = data;
	while (rest > 0) {
		written = write(fd, p, rest);
		if (written < 0) {
			fprintf(stderr, "write error: %m\n");
			return -1;
		}
		rest -= written;
		p += written;
	}

	return 0;
}

struct qsort_context {
	size_t size;
	razor_compare_with_data_func_t compare;
	void *data;
};

static void
qsort_swap(void *p1, void *p2, size_t size)
{
	char buffer[size];

	memcpy(buffer, p1, size);
	memcpy(p1, p2, size);
	memcpy(p2, buffer, size);
}

static void
__qsort_with_data(void *base, size_t nelem, uint32_t *map,
		  struct qsort_context *ctx)
{
	void *p, *start, *end, *pivot;
	uint32_t *mp, *mstart, *mend, tmp;
	int left, right, result;
	size_t size = ctx->size;

	p = base;
	start = base;
	end = base + nelem * size;
	mp = map;
	mstart = map;
	mend = map + nelem;
	pivot = base + (random() % nelem) * size;

	while (p < end) {
		result = ctx->compare(p, pivot, ctx->data);
		if (result < 0) {
			qsort_swap(p, start, size);
			tmp = *mp;
			*mp = *mstart;
			*mstart = tmp;
			if (start == pivot)
				pivot = p;
			start += size;
			mstart++;
			p += size;
			mp++;
		} else if (result == 0) {
			p += size;
			mp++;
		} else {
 			end -= size;
			mend--;
			qsort_swap(p, end, size);
			tmp = *mp;
			*mp = *mend;
			*mend = tmp;
			if (end == pivot)
				pivot = p;
		}
	}

	left = (start - base) / size;
	right = (base + nelem * size - end) / size;
	if (left > 1)
		__qsort_with_data(base, left, map, ctx);
	if (right > 1)
		__qsort_with_data(end, right, mend, ctx);
}

uint32_t *
razor_qsort_with_data(void *base, size_t nelem, size_t size,
		      razor_compare_with_data_func_t compare, void *data)
{
	struct qsort_context ctx;
	uint32_t *map;
	int i;

	if (nelem == 0)
		return NULL;

	ctx.size = size;
	ctx.compare = compare;
	ctx.data = data;

	map = malloc(nelem * sizeof (uint32_t));
	for (i = 0; i < nelem; i++)
		map[i] = i;

	__qsort_with_data(base, nelem, map, &ctx);

	return map;
}
