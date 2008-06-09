#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include "razor.h"
#include "razor-internal.h"

static const char system_repo_filename[] = "system.repo";
static const char next_repo_filename[] = "system-next.repo";
static const char razor_root_path[] = "/var/lib/razor";

struct razor_root {
	struct razor_set *system;
	struct razor_set *next;
	int fd;
	char path[PATH_MAX];
	char new_path[PATH_MAX];
};

int
razor_root_create(const char *root)
{	
	struct stat buf;
	struct razor_set *set;
	char path[PATH_MAX];

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
	if (stat(root, &buf) == 0) {
		fprintf(stderr,
			"a razor install root is already initialized\n");
		return -1;
	}
	if (razor_set_write(set, path) < 0) {
		fprintf(stderr, "could not write initial package set\n");
		return -1;
	}
	razor_set_destroy(set);

	return 0;
}

struct razor_root *
razor_root_open(const char *root, int flags)
{
	struct razor_root *image;

	image = malloc(sizeof *image);
	if (image == NULL)
		return NULL;

	/* Create the new next repo file up front to ensure exclusive
	 * access. */
	snprintf(image->new_path, sizeof image->new_path,
		 "%s%s/%s", root, root, next_repo_filename);
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

struct razor_transaction *
razor_root_create_transaction(struct razor_root *image,
			      struct razor_set *upstream)
{
	/* FIXME: This should take a number of upstream repos. */
	return razor_transaction_create(image->system, upstream);
}

int
razor_root_close(struct razor_root *image)
{
	unlink(image->new_path);
	close(image->fd);
	free(image);

	return 0;
}

void
razor_root_update(struct razor_root *root, struct razor_set *next)
{
	razor_set_write_to_fd(next, root->fd);
	root->next = next;

	/* Sync the new repo file so the new package set is on disk
	 * before we start upgrading. */
	fsync(root->fd);
	printf("wrote %s\n", root->new_path);
}

int
razor_root_commit(struct razor_root *image)
{
	/* Make it so. */
	rename(image->new_path, image->path);
	printf("renamed %s to %s\n", image->new_path, image->path);
	close(image->fd);
	free(image);

	return 0;
}

void
razor_root_diff(struct razor_root *root,
		razor_package_callback_t callback, void *data)
{
	return razor_set_diff(root->system, root->next, callback, data);
}
