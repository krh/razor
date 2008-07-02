/*
 * Copyright (C) 2008  Kristian Høgsberg <krh@redhat.com>
 * Copyright (C) 2008  Red Hat, Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "razor.h"
#include "razor-internal.h"

static const char system_repo_filename[] = "system.rzdb";
static const char system_repo_details_filename[] = "system-details.rzdb";
static const char system_repo_files_filename[] = "system-files.rzdb";

static const char next_repo_filename[] = "system-next.rzdb";
static const char razor_root_path[] = "/var/lib/razor";

struct razor_root {
	struct razor_set *system;
	struct razor_set *next;
	int fd;
	char path[PATH_MAX];
	char new_path[PATH_MAX];
};

RAZOR_EXPORT int
razor_root_create(const char *root)
{
	struct stat buf;
	struct razor_set *set;
	char path[PATH_MAX], details_path[PATH_MAX], files_path[PATH_MAX];

	assert (root != NULL);

	if (stat(root, &buf) < 0) {
		if (mkdir(root, 0777) < 0) {
			fprintf(stderr,
				"could not create install root \"%s\"\n",
				root);
			return -1;
		}
		fprintf(stderr, "created install root \"%s\"\n", root);
	} else if (!S_ISDIR(buf.st_mode)) {
		fprintf(stderr,
			"install root \"%s\" exists, but is not a directory\n",
			root);
		return -1;
	}

	snprintf(path, sizeof path, "%s/%s",
		 razor_root_path, system_repo_filename);
	if (razor_create_dir(root, path) < 0) {
		fprintf(stderr, "could not create %s%s\n",
			root, razor_root_path);
		return -1;
	}

	set = razor_set_create();
	snprintf(path, sizeof path, "%s%s/%s",
		 root, razor_root_path, system_repo_filename);
	snprintf(details_path, sizeof details_path, "%s%s/%s",
		 root, razor_root_path, system_repo_details_filename);
	snprintf(files_path, sizeof files_path, "%s%s/%s",
		 root, razor_root_path, system_repo_files_filename);
	if (stat(path, &buf) == 0) {
		fprintf(stderr,
			"a razor install root is already initialized\n");
		return -1;
	}
	if (razor_set_write(set, path, RAZOR_REPO_FILE_MAIN) < 0 ||
	    razor_set_write(set, details_path, RAZOR_REPO_FILE_DETAILS) < 0 ||
	    razor_set_write(set, files_path, RAZOR_REPO_FILE_FILES) < 0 ) {
		fprintf(stderr, "could not write initial package set\n");
		return -1;
	}
	razor_set_destroy(set);

	return 0;
}

RAZOR_EXPORT struct razor_root *
razor_root_open(const char *root)
{
	struct razor_root *image;

	assert (root != NULL);

	image = malloc(sizeof *image);
	if (image == NULL)
		return NULL;

	/* Create the new next repo file up front to ensure exclusive
	 * access. */
	snprintf(image->new_path, sizeof image->new_path,
		 "%s%s/%s", root, razor_root_path, next_repo_filename);
	image->fd = open(image->new_path,
			 O_CREAT | O_WRONLY | O_TRUNC | O_EXCL, 0666);
	if (image->fd < 0) {
		fprintf(stderr, "failed to get lock file, "
			"maybe previous operation crashed?\n");

		/* FIXME: Use fcntl advisory locking on the system
		 * package set file to figure out whether previous
		 * operation crashed or is still in progress. */

		free(image);
		return NULL;
	}

	snprintf(image->path, sizeof image->path,
		 "%s%s/%s", root, razor_root_path, system_repo_filename);
	image->system = razor_set_open(image->path);
	if (image->system == NULL) {
		unlink(image->new_path);
		close(image->fd);
		free(image);
		return NULL;
	}

	return image;
}

RAZOR_EXPORT struct razor_set *
razor_root_open_read_only(const char *root)
{
	char path[PATH_MAX];

	assert (root != NULL);

	snprintf(path, sizeof path, "%s%s/%s",
		 root, razor_root_path, system_repo_filename);

	return razor_set_open(path);
}

RAZOR_EXPORT struct razor_set *
razor_root_get_system_set(struct razor_root *root)
{
	assert (root != NULL);

	return root->system;
}

RAZOR_EXPORT int
razor_root_close(struct razor_root *root)
{
	assert (root != NULL);

	razor_set_destroy(root->system);
	unlink(root->new_path);
	close(root->fd);
	free(root);

	return 0;
}

RAZOR_EXPORT void
razor_root_update(struct razor_root *root, struct razor_set *next)
{
	assert (root != NULL);
	assert (next != NULL);

	razor_set_write_to_fd(next, root->fd, RAZOR_REPO_FILE_MAIN);
	root->next = next;

	/* Sync the new repo file so the new package set is on disk
	 * before we start upgrading. */
	fsync(root->fd);
	printf("wrote %s\n", root->new_path);
}

RAZOR_EXPORT int
razor_root_commit(struct razor_root *root)
{
	assert (root != NULL);

	/* Make it so. */
	rename(root->new_path, root->path);
	printf("renamed %s to %s\n", root->new_path, root->path);
	razor_set_destroy(root->system);
	close(root->fd);
	free(root);

	return 0;
}
