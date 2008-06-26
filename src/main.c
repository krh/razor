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
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <curl/curl.h>
#include <fnmatch.h>
#include <errno.h>
#include "razor.h"

static const char system_repo_filename[] = "system.repo";
static const char next_repo_filename[] = "system-next.repo";
static const char rawhide_repo_filename[] = "rawhide.repo";
static const char updated_repo_filename[] = "system-updated.repo";
static const char install_root[] = "install";
static const char *repo_filename = system_repo_filename;
static const char *yum_url;

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static struct razor_package_iterator *
create_iterator_from_argv(struct razor_set *set, int argc, const char *argv[])
{
	struct razor_package_query *query;
	struct razor_package_iterator *iter;
	struct razor_package *package;
	const char *name, *version, *arch, *pattern;
	int i, count;

	if (argc == 0)
		return razor_package_iterator_create(set);

	query = razor_package_query_create(set);

	for (i = 0; i < argc; i++) {
		iter = razor_package_iterator_create(set);
		pattern = argv[i];
		count = 0;
		while (razor_package_iterator_next(iter, &package,
						   &name, &version, &arch)) {
			if (fnmatch(pattern, name, 0) != 0)
				continue;

			razor_package_query_add_package(query, package);
			count++;
		}
		razor_package_iterator_destroy(iter);

		if (count == 0)
			fprintf(stderr,
				"no package matches \"%s\"\n", pattern);
	}

	return razor_package_query_finish(query);
}

#define LIST_PACKAGES_ONLY_NAMES 0x01

static void
list_packages(struct razor_package_iterator *iter, uint32_t flags)
{
	struct razor_package *package;
	const char *name, *version, *arch;

	while (razor_package_iterator_next(iter, &package,
					   &name, &version, &arch)) {
		if (flags & LIST_PACKAGES_ONLY_NAMES)
			printf("%s\n", name);
		else
			printf("%s-%s.%s\n", name, version, arch);
	}
}

static int
command_list(int argc, const char *argv[])
{
	struct razor_package_iterator *pi;
	struct razor_set *set;
	uint32_t flags = 0;
	int i = 0;

	if (i < argc && strcmp(argv[i], "--only-names") == 0) {
		flags |= LIST_PACKAGES_ONLY_NAMES;
		i++;
	}

	set = razor_set_open(repo_filename);
	pi = create_iterator_from_argv(set, argc - i, argv + i);
	list_packages(pi, flags);
	razor_package_iterator_destroy(pi);
	razor_set_destroy(set);

	return 0;
}

static int
list_properties(const char *package_name, uint32_t type)
{
	struct razor_set *set;
	struct razor_property *property;
	struct razor_package *package;
	struct razor_property_iterator *pi;
	const char *name, *version;
	uint32_t flags;

	set = razor_set_open(repo_filename);
	if (package_name) {
		package = razor_set_get_package(set, package_name);
		if (!package) {
			fprintf(stderr, "no package named \"%s\"\n", package_name);
			return 1;
		}
	} else
		package = NULL;

	pi = razor_property_iterator_create(set, package);
	while (razor_property_iterator_next(pi, &property,
					    &name, &flags, &version)) {
		if ((flags & RAZOR_PROPERTY_TYPE_MASK) != type)
			continue;
		printf("%s", name);
		if (version[0] != '\0')
			printf(" %s %s",
			       razor_property_relation_to_string(property),
			       version);

		if (flags & ~(RAZOR_PROPERTY_RELATION_MASK | RAZOR_PROPERTY_TYPE_MASK)) {
			printf(" [");
			if (flags & RAZOR_PROPERTY_PRE)
				printf(" pre");
			if (flags & RAZOR_PROPERTY_POST)
				printf(" post");
			if (flags & RAZOR_PROPERTY_PREUN)
				printf(" preun");
			if (flags & RAZOR_PROPERTY_POSTUN)
				printf(" postun");
			printf(" ]");
		}
		printf("\n");
	}
	razor_property_iterator_destroy(pi);

	razor_set_destroy(set);

	return 0;
}

static int
command_list_requires(int argc, const char *argv[])
{
	return list_properties(argv[0], RAZOR_PROPERTY_REQUIRES);
}

static int
command_list_provides(int argc, const char *argv[])
{
	return list_properties(argv[0], RAZOR_PROPERTY_PROVIDES);
}

static int
command_list_obsoletes(int argc, const char *argv[])
{
	return list_properties(argv[0], RAZOR_PROPERTY_OBSOLETES);
}

static int
command_list_conflicts(int argc, const char *argv[])
{
	return list_properties(argv[0], RAZOR_PROPERTY_CONFLICTS);
}

static int
command_list_files(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;
	if (razor_set_open_files(set, "system-files.repo"))
		return 1;

	razor_set_list_files(set, argv[0]);
	razor_set_destroy(set);

	return 0;
}

static int
command_list_file_packages(int argc, const char *argv[])
{
	struct razor_set *set;
	struct razor_package_iterator *pi;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;
	if (razor_set_open_files(set, "system-files.repo"))
		return 1;

	pi = razor_package_iterator_create_for_file(set, argv[0]);
	list_packages(pi, 0);
	razor_package_iterator_destroy(pi);

	razor_set_destroy(set);

	return 0;
}

static int
command_list_package_files(int argc, const char *argv[])
{
	struct razor_set *set;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;
	if (razor_set_open_files(set, "system-files.repo"))
		return 1;

	razor_set_list_package_files(set, argv[0]);
	razor_set_destroy(set);

	return 0;
}

static int
list_property_packages(const char *ref_name,
		       const char *ref_version,
		       uint32_t type)
{
	struct razor_set *set;
	struct razor_property *property;
	struct razor_property_iterator *prop_iter;
	struct razor_package_iterator *pkg_iter;
	const char *name, *version;
	uint32_t flags;

	if (ref_name == NULL)
		return 0;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;

	prop_iter = razor_property_iterator_create(set, NULL);
	while (razor_property_iterator_next(prop_iter, &property,
					    &name, &flags, &version)) {
		if (strcmp(ref_name, name) != 0)
			continue;
		if (ref_version &&
		    (flags & RAZOR_PROPERTY_RELATION_MASK) == RAZOR_PROPERTY_EQUAL &&
		    strcmp(ref_version, version) != 0)
			continue;
		if ((flags & RAZOR_PROPERTY_TYPE_MASK) != type)
			continue;

		pkg_iter =
			razor_package_iterator_create_for_property(set,
								   property);
		list_packages(pkg_iter, 0);
		razor_package_iterator_destroy(pkg_iter);
	}
	razor_property_iterator_destroy(prop_iter);

	return 0;
}

static int
command_what_requires(int argc, const char *argv[])
{
	return list_property_packages(argv[0], argv[1],
				      RAZOR_PROPERTY_REQUIRES);
}

static int
command_what_provides(int argc, const char *argv[])
{
	return list_property_packages(argv[0], argv[1],
				      RAZOR_PROPERTY_PROVIDES);
}

static int
show_progress(void *clientp,
	      double dltotal, double dlnow, double ultotal, double ulnow)
{
	const char *file = clientp;

	if (!dlnow < dltotal)
		fprintf(stderr, "\rdownloading %s, %dkB/%dkB",
			file, (int) dlnow / 1024, (int) dltotal / 1024);

	return 0;
}

static int
download_if_missing(const char *url, const char *file)
{
	CURL *curl;
	struct stat buf;
	char error[256];
	FILE *fp;
	CURLcode res;
	long response;

	curl = curl_easy_init();
	if (curl == NULL)
		return 1;

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
	curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, show_progress);
	curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, file);

	if (stat(file, &buf) < 0) {
		fp = fopen(file, "w");
		if (fp == NULL) {
			fprintf(stderr,
				"failed to open %s for writing\n", file);
			return -1;
		}
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		res = curl_easy_perform(curl);
		fclose(fp);
		if (res != CURLE_OK) {
			fprintf(stderr, "curl error: %s\n", error);
			unlink(file);
			return -1;
		}
		res = curl_easy_getinfo(curl,
					CURLINFO_RESPONSE_CODE, &response);
		if (res != CURLE_OK) {
			fprintf(stderr, "curl error: %s\n", error);
                        unlink(file);
                        return -1;
		}
		if (response != 200) {
			fprintf(stderr, " - failed %ld\n", response);
                        unlink(file);
                        return -1;
		}
		fprintf(stderr, "\n");
	}

	curl_easy_cleanup(curl);

	return 0;
}

#define YUM_URL "http://download.fedora.redhat.com" \
	"/pub/fedora/linux/development/i386/os"

static int
command_import_yum(int argc, const char *argv[])
{
	struct razor_set *set;
	char buffer[512];

	printf("downloading from %s.\n", yum_url);
	snprintf(buffer, sizeof buffer,
		 "%s/repodata/primary.xml.gz", yum_url);
	if (download_if_missing(buffer, "primary.xml.gz") < 0)
		return -1;
	snprintf(buffer, sizeof buffer,
		 "%s/repodata/filelists.xml.gz", yum_url);
	if (download_if_missing(buffer, "filelists.xml.gz") < 0)
		return -1;

	set = razor_set_create_from_yum();
	if (set == NULL)
		return 1;
	razor_set_write(set, rawhide_repo_filename, RAZOR_REPO_FILE_MAIN);
	razor_set_write(set, "rawhide-details.repo", RAZOR_REPO_FILE_DETAILS);
	razor_set_write(set, "rawhide-files.repo", RAZOR_REPO_FILE_FILES);
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
	razor_set_write(set, repo_filename, RAZOR_REPO_FILE_MAIN);
	razor_set_write(set, "system-details.repo", RAZOR_REPO_FILE_DETAILS);
	razor_set_write(set, "system-files.repo", RAZOR_REPO_FILE_FILES);
	razor_set_destroy(set);
	printf("wrote %s\n", repo_filename);

	return 0;
}

static int
mark_packages_for_update(struct razor_transaction *trans,
			 struct razor_set *set, const char *pattern)
{
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *name, *version, *arch;
	int matches = 0;

	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		if (pattern && fnmatch(pattern, name, 0) == 0) {
			razor_transaction_update_package(trans, package);
			matches++;
		}
	}
	razor_package_iterator_destroy(pi);

	return matches;
}

static int
mark_packages_for_removal(struct razor_transaction *trans,
			  struct razor_set *set, const char *pattern)
{
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *name, *version, *arch;
	int matches = 0;

	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		if (pattern && fnmatch(pattern, name, 0) == 0) {
			razor_transaction_remove_package(trans, package);
			matches++;
		}
	}
	razor_package_iterator_destroy(pi);

	return matches;
}

static int
command_update(int argc, const char *argv[])
{
	struct razor_set *set, *upstream;
	struct razor_transaction *trans;
	int i, errors;

	set = razor_set_open(repo_filename);
	upstream = razor_set_open(rawhide_repo_filename);
	if (set == NULL || upstream == NULL)
		return 1;

	trans = razor_transaction_create(set, upstream);
	if (argc == 0)
		razor_transaction_update_all(trans);
	for (i = 0; i < argc; i++) {
		if (mark_packages_for_update(trans, set, argv[i]) == 0) {
			fprintf(stderr, "no match for %s\n", argv[i]);
			return 1;
		}
	}

	razor_transaction_resolve(trans);
	errors = razor_transaction_describe(trans);
	if (errors) {
		fprintf(stderr, "unresolved dependencies\n");
		return 1;
	}

	set = razor_transaction_finish(trans);
	razor_set_write(set, updated_repo_filename, RAZOR_REPO_FILE_MAIN);
	razor_set_destroy(set);
	razor_set_destroy(upstream);
	printf("wrote system-updated.repo\n");

	return 0;
}

static int
command_remove(int argc, const char *argv[])
{
	struct razor_set *set, *upstream;
	struct razor_transaction *trans;
	int i, errors;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;

	upstream = razor_set_create();
	trans = razor_transaction_create(set, upstream);
	for (i = 0; i < argc; i++) {
		if (mark_packages_for_removal(trans, set, argv[i]) == 0) {
			fprintf(stderr, "no match for %s\n", argv[i]);
			return 1;
		}
	}

	errors = razor_transaction_resolve(trans);
	if (errors)
		return 1;

	set = razor_transaction_finish(trans);
	razor_set_write(set, updated_repo_filename, RAZOR_REPO_FILE_MAIN);
	razor_set_destroy(set);
	razor_set_destroy(upstream);
	printf("wrote system-updated.repo\n");

	return 0;
}

static void
print_diff(enum razor_diff_action action,
	   struct razor_package *package,
	   const char *name,
	   const char *version,
	   const char *arch,
	   void *data)
{
	if (action == RAZOR_DIFF_ACTION_ADD)
		printf("install %s-%s.%s\n", name, version, arch);
	if (action == RAZOR_DIFF_ACTION_REMOVE)
		printf("remove %s-%s.%s\n", name, version, arch);
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

static int
command_import_rpms(int argc, const char *argv[])
{
	DIR *dir;
	struct dirent *de;
	struct razor_importer *importer;
	struct razor_set *set;
	struct razor_rpm *rpm;
	int len, imported_count = 0;
	char filename[256];
	const char *dirname = argv[0];

	if (dirname == NULL) {
		fprintf(stderr, "usage: razor import-rpms DIR\n");
		return -1;
	}

	dir = opendir(dirname);
	if (dir == NULL) {
		fprintf(stderr, "couldn't read dir %s\n", dirname);
		return -1;
	}

	importer = razor_importer_create();

	while (de = readdir(dir), de != NULL) {
		len = strlen(de->d_name);
		if (len < 5 || strcmp(de->d_name + len - 4, ".rpm") != 0)
		    continue;
		snprintf(filename, sizeof filename,
			 "%s/%s", dirname, de->d_name);
		rpm = razor_rpm_open(filename);
		if (rpm == NULL) {
			fprintf(stderr,
				"failed to open rpm \"%s\"\n", filename);
			continue;
		}
		if (razor_importer_add_rpm(importer, rpm)) {
			fprintf(stderr, "couldn't import %s\n", filename);
			break;
		}
		razor_rpm_close(rpm);

		printf("\rimporting %d", ++imported_count);
		fflush(stdout);
	}

	if (de != NULL) {
		razor_importer_destroy(importer);
		return -1;
	}

	printf("\nsaving\n");
	set = razor_importer_finish(importer);

	razor_set_write(set, repo_filename, RAZOR_REPO_FILE_MAIN);
	razor_set_write(set, "system-details.repo", RAZOR_REPO_FILE_DETAILS);
	razor_set_write(set, "system-files.repo", RAZOR_REPO_FILE_FILES);
	razor_set_destroy(set);
	printf("wrote %s\n", repo_filename);

	return 0;
}

static const char *
rpm_filename(const char *name, const char *version, const char *arch)
{
	static char file[PATH_MAX];
 	const char *v;
 
 	/* Skip epoch */
	v = strchr(version, ':');
 	if (v != NULL)
 		v = v + 1;
 	else
		v = version;

	snprintf(file, sizeof file, "%s-%s.%s.rpm", name, v, arch);

	return file;
}

static int
download_packages(struct razor_set *system, struct razor_set *next)
{
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *name, *version, *arch;
	char file[PATH_MAX], url[256];
	int errors;
 
	pi = razor_set_create_install_iterator(system, next);
	errors = 0;
	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		snprintf(url, sizeof url,
			 "%s/Packages/%s",
			 yum_url, rpm_filename(name, version, arch));
		snprintf(file, sizeof file,
			 "rpms/%s", rpm_filename(name, version, arch));
		if (download_if_missing(url, file) < 0)
			errors++;
	}
	razor_package_iterator_destroy(pi);

	if (errors > 0) {
		fprintf(stderr, "failed to download %d packages\n", errors);
                return -1;
        }

	return 0;
}

static int
install_packages(struct razor_set *system, struct razor_set *next)
{
	struct razor_package_iterator *pi;
	struct razor_package *package;
	struct razor_rpm *rpm;
	const char *name, *version, *arch;
	char file[PATH_MAX];

	pi = razor_set_create_install_iterator(system, next);
	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		printf("install %s-%s\n", name, version);

		snprintf(file, sizeof file,
			 "rpms/%s", rpm_filename(name, version, arch));
		rpm = razor_rpm_open(file);
		if (rpm == NULL) {
			fprintf(stderr, "failed to open rpm %s\n", file);
			return -1;
		}
		if (razor_rpm_install(rpm, install_root) < 0) {
			fprintf(stderr,
				"failed to install rpm %s\n", file);
			return -1;
		}
		razor_rpm_close(rpm);
	}
	razor_package_iterator_destroy(pi);

	return 0;
}

static int
command_install(int argc, const char *argv[])
{
	struct razor_root *root;
	struct razor_set *system, *upstream, *next;
	struct razor_transaction *trans;
	int i = 0, dependencies = 1;

	if (i < argc && strcmp(argv[i], "--no-dependencies") == 0) {
		dependencies = 0;
		i++;
	}

	root = razor_root_open(install_root);
	if (root == NULL)
		return 1;

	system = razor_root_get_system_set(root);
	upstream = razor_set_open(rawhide_repo_filename);
	trans = razor_transaction_create(system, upstream);

	for (; i < argc; i++) {
		if (mark_packages_for_update(trans, upstream, argv[i]) == 0) {
			fprintf(stderr, "no package matched %s\n", argv[i]);
			razor_root_close(root);
			return 1;
		}
	}

	if (dependencies) {
		razor_transaction_resolve(trans);
		if (razor_transaction_describe(trans) > 0) {
			razor_root_close(root);
			return 1;
		}
	}

	next = razor_transaction_finish(trans);

	razor_root_update(root, next);

	if (mkdir("rpms", 0777) && errno != EEXIST) {
		fprintf(stderr, "failed to create rpms directory.\n");
		razor_root_close(root);
		return 1;
	}

	if (download_packages(system, next) < 0) {
		razor_root_close(root);
                return 1;
        }

	install_packages(system, next);

	razor_set_destroy(next);
	razor_set_destroy(upstream);

	return razor_root_commit(root);
}

static int
command_init(int argc, const char *argv[])
{
	return razor_root_create(install_root);
}

static int
command_download(int argc, const char *argv[])
{
	struct razor_set *set;
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *pattern = argv[0], *name, *version, *arch;
	char url[256], file[256];
	int matches = 0;

	if (mkdir("rpms", 0777) && errno != EEXIST) {
		fprintf(stderr, "failed to create rpms directory.\n");
		return 1;
	}

	set = razor_set_open(rawhide_repo_filename);
	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		if (pattern && fnmatch(pattern, name, 0) != 0)
			continue;

		matches++;
		snprintf(url, sizeof url,
			 "%s/Packages/%s-%s.%s.rpm",
			 yum_url, name, version, arch);
		snprintf(file, sizeof file,
			 "rpms/%s-%s.%s.rpm", name, version, arch);
		download_if_missing(url, file);
	}
	razor_package_iterator_destroy(pi);
	razor_set_destroy(set);

	if (matches == 0)
		fprintf(stderr, "no packages matched \"%s\"\n", pattern);
	else if (matches == 1)
		fprintf(stderr, "downloaded 1 package\n");
	else
		fprintf(stderr, "downloaded %d packages\n", matches);

	return 0;
}

static int
command_info(int argc, const char *argv[])
{
	struct razor_set *set;
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *pattern = argv[0], *name, *version, *arch;
	const char *summary, *description, *url, *license;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;
	if (razor_set_open_details(set, "system-details.repo"))
		return 1;
	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		if (pattern && fnmatch(pattern, name, 0) != 0)
			continue;

		razor_package_get_details (set, package, &summary, &description,
					   &url, &license);

		printf ("Name:        %s\n", name);
		printf ("Arch:        %s\n", arch);
		printf ("Version:     %s\n", version);
		printf ("URL:         %s\n", url);
		printf ("License:     %s\n", license);
		printf ("Summary:     %s\n", summary);
		printf ("Description:\n");
		printf ("%s\n", description);
		printf ("\n");
	}
	razor_package_iterator_destroy(pi);
	razor_set_destroy(set);

	return 0;
}

static struct {
	const char *name;
	const char *description;
	int (*func)(int argc, const char *argv[]);
} razor_commands[] = {
	{ "list", "list all packages", command_list },
	{ "list-requires", "list all requires for the given package", command_list_requires },
	{ "list-provides", "list all provides for the given package", command_list_provides },
	{ "list-obsoletes", "list all obsoletes for the given package", command_list_obsoletes },
	{ "list-conflicts", "list all conflicts for the given package", command_list_conflicts },
	{ "list-files", "list files for package set", command_list_files },
	{ "list-file-packages", "list packages owning file", command_list_file_packages },
	{ "list-package-files", "list files in package", command_list_package_files },
	{ "what-requires", "list the packages that have the given requires", command_what_requires },
	{ "what-provides", "list the packages that have the given provides", command_what_provides },
	{ "import-yum", "import yum metadata files", command_import_yum },
	{ "import-rpmdb", "import the system rpm database", command_import_rpmdb },
	{ "import-rpms", "import rpms from the given directory", command_import_rpms },
	{ "update", "update all or specified packages", command_update },
	{ "remove", "remove specified packages", command_remove },
	{ "diff", "show diff between two package sets", command_diff },
	{ "install", "install rpm", command_install },
	{ "init", "init razor root", command_init },
	{ "download", "download packages", command_download },
	{ "info", "display package details", command_info }
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

	yum_url = getenv("YUM_URL");
	if (yum_url == NULL)
		yum_url = YUM_URL;

	if (argc < 2)
		return usage();

	for (i = 0; i < ARRAY_SIZE(razor_commands); i++)
		if (strcmp(razor_commands[i].name, argv[1]) == 0)
			return razor_commands[i].func(argc - 2, argv + 2);

	return usage();
}
