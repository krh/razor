#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "razor.h"

static const char *repo_filename = "system.repo";
static const char *rawhide_repo_filename = "rawhide.repo";
static const char *updated_repo_filename = "system-updated.repo";

static int
command_list(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	razor_set_list(set);
	razor_set_destroy(set);

	return 0;
}

static int
command_list_requires(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	razor_set_list_requires(set, argv[2]);
	razor_set_destroy(set);

	return 0;
}

static int
command_list_provides(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	razor_set_list_provides(set, argv[2]);
	razor_set_destroy(set);

	return 0;
}

static int
command_what_requires(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	razor_set_list_requires_packages(set, argv[2], argv[3]);
	razor_set_destroy(set);

	return 0;
}

static int
command_what_provides(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	razor_set_list_provides_packages(set, argv[2], argv[3]);
	razor_set_destroy(set);

	return 0;
}

static int
command_import_yum(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_create_from_yum_filelist(STDIN_FILENO);
	if (set == NULL)
		return 1;
	razor_set_write(set, rawhide_repo_filename);
	razor_set_destroy(set);
	printf("wrote %s\n", rawhide_repo_filename);

	return 0;
}

static int
command_import_rpmdb(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_create_from_rpmdb();
	if (set == NULL)
		return 1;
	razor_set_write(set, repo_filename);
	razor_set_destroy(set);
	printf("wrote %s\n", repo_filename);

	return 0;
}

static int
command_validate(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;
	razor_set_list_unsatisfied(set);
	razor_set_destroy(set);

	return 0;
}

static int
command_update(int argc, const char *argv[])
{
	struct razor_set *set, *upstream;

	set = razor_set_open(repo_filename);
	upstream = razor_set_open(rawhide_repo_filename);
	if (set == NULL || upstream == NULL)
		return 1;
	set = razor_set_update(set, upstream, argc - 2, argv + 2);
	razor_set_write(set, updated_repo_filename);
	razor_set_destroy(set);
	razor_set_destroy(upstream);
	printf("wrote system-updated.repo\n");

	return 0;
}

static void
print_diff(const char *name,
	   const char *old_version, const char *new_version, void *data)
{
	if (old_version)
		printf("removing %s %s\n", name, old_version);
	else
		printf("install %s %s\n", name, new_version);
}

static int
command_diff(int argc, const char *argv[])
{
	struct razor_set *set, *updated;

	set = razor_set_open(repo_filename);
	updated = razor_set_open(updated_repo_filename);
	if (set == NULL || updated == NULL)
		return 1;

	razor_set_diff(set, updated, print_diff, NULL);	

	razor_set_destroy(set);
	razor_set_destroy(updated);

	return 0;
}

static struct {
	const char *name;
	const char *description;
	int (*func)(int argc, const char *argv[]);
} razor_commands[] = {
	{ "list", "list all packages", command_list },
	{ "list-requires", "list all requires or requires for the given package", command_list_requires },
	{ "list-provides", "list all provides or provides for the give package", command_list_provides },
	{ "what-requires", "list the packages that have the given requires", command_what_requires },
	{ "what-provides", "list the packages that have the given provides", command_what_provides },
	{ "import-yum", "import yum filelist.xml on stdin", command_import_yum },
	{ "import-rpmdb", "import the system rpm database", command_import_rpmdb },
	{ "validate", "validate a package set", command_validate },
	{ "update", "update all or specified packages", command_update },
	{ "diff", "show diff between two package sets", command_diff }
};

static int
usage(void)
{
	int i;

	printf("usage:\n");
	for (i = 0; i < ARRAY_SIZE(razor_commands); i++)
		printf("  %-20s%s\n",
		       razor_commands[i].name, razor_commands[i].description);

	return 1;
}

int
main(int argc, const char *argv[])
{
	char *repo;
	int i;

	repo = getenv("RAZOR_REPO");
	if (repo != NULL)
		repo_filename = repo;

	if (argc < 2)
		return usage();

	for (i = 0; i < ARRAY_SIZE(razor_commands); i++)
		if (strcmp(razor_commands[i].name, argv[1]) == 0)
			return razor_commands[i].func(argc - 2, argv + 2);

	return usage();
}
