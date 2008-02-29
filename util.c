#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
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
	for (slash = path; slash[1] != '\0'; slash = next) {
		next = strchr(slash + 1, '/');
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
