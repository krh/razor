#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <curl/curl.h>
#include <fnmatch.h>
#include "razor.h"
#include "razor-internal.h"

static const char system_repo_filename[] = "system.repo";
static const char next_repo_filename[] = "system-next.repo";
static const char rawhide_repo_filename[] = "rawhide.repo";
static const char updated_repo_filename[] = "system-updated.repo";
static const char razor_root_path[] = "/var/lib/razor";
static const char root[] = "install";
static const char *repo_filename = system_repo_filename;

static int
command_list(int argc, const char *argv[])
{
	struct razor_set *set;
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *pattern = argv[0], *name, *version;

	set = razor_set_open(repo_filename);
	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &package, &name, &version)) {
		if (pattern && fnmatch(pattern, name, 0) != 0)
			continue;

		printf("%s-%s\n", name, version);
	}
	razor_package_iterator_destroy(pi);
	razor_set_destroy(set);

	return 0;
}

static int
list_properties(const char *package_name,
		enum razor_property_type required_type)
{
	struct razor_set *set;
	struct razor_property *property;
	struct razor_package *package;
	struct razor_property_iterator *pi;
	const char *name, *version;
	enum razor_property_type type;
	enum razor_version_relation relation;

	set = razor_set_open(repo_filename);
	if (package_name)
		package = razor_set_get_package(set, package_name);
	else
		package = NULL;

	pi = razor_property_iterator_create(set, package);
	while (razor_property_iterator_next(pi, &property,
					    &name, &relation, &version,
					    &type)) {
		if (type != required_type)
			continue;
		if (version[0] == '\0')
			printf("%s\n", name);
		else
			printf("%s %s %s\n", name,
			       razor_version_relations[relation], version);
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
	razor_set_list_files(set, argv[0]);
	razor_set_destroy(set);

	return 0;
}

static int
command_list_file_packages(int argc, const char *argv[])
{
	struct razor_set *set;
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *name, *version;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;

	pi = razor_package_iterator_create_for_file(set, argv[0]);
	while (razor_package_iterator_next(pi, &package, &name, &version))
		printf("%s-%s\n", name, version);
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
	razor_set_list_package_files(set, argv[0]);
	razor_set_destroy(set);

	return 0;
}

static void
list_packages_for_property(struct razor_set *set,
			   struct razor_property *property)
{
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *name, *version;

	pi = razor_package_iterator_create_for_property(set, property);
	while (razor_package_iterator_next(pi, &package, &name, &version))
		printf("%s-%s\n", name, version);
	razor_package_iterator_destroy(pi);
}

static int
list_property_packages(const char *ref_name,
		       const char *ref_version,
		       enum razor_property_type ref_type)
{
	struct razor_set *set;
	struct razor_property *property;
	struct razor_property_iterator *pi;
	const char *name, *version;
	enum razor_property_type type;
	enum razor_version_relation relation;

	if (ref_name == NULL)
		return 0;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;

	pi = razor_property_iterator_create(set, NULL);
	while (razor_property_iterator_next(pi, &property,
					    &name, &relation, &version,
					    &type)) {
		if (strcmp(ref_name, name) != 0)
			continue;
		if (ref_version && relation == RAZOR_VERSION_EQUAL &&
		    strcmp(ref_version, version) != 0)
			continue;
		if (ref_type != type)
			continue;

		list_packages_for_property(set, property);
	}
	razor_property_iterator_destroy(pi);

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
	else
		fprintf(stderr, "\n");

	return 0;
}

static int
download_if_missing(CURL *curl, const char *url, const char *file)
{
	struct stat buf;
	char error[256];
	FILE *fp;
	CURLcode res;
	char buffer[256];

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
	curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, show_progress);
	curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, file);

	if (stat(file, &buf) < 0) {
		fp = fopen(file, "w");
		snprintf(buffer, sizeof buffer, "%s/%s", url, file);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
		curl_easy_setopt(curl, CURLOPT_URL, buffer);
		res = curl_easy_perform(curl);
		fclose(fp);
		if (res != CURLE_OK) {
			fprintf(stderr, "curl error: %s\n", error);
			unlink(file);
			return -1;
		}
	}

	return 0;
}

#define REPO_URL "http://download.fedora.redhat.com" \
	"/pub/fedora/linux/development/i386/os/repodata"

static int
command_import_yum(int argc, const char *argv[])
{
	struct razor_set *set;
	CURL *curl;

	curl = curl_easy_init();
	if (curl == NULL)
		return 1;

	if (download_if_missing(curl, REPO_URL, "primary.xml.gz") < 0)
		return -1;
	if (download_if_missing(curl, REPO_URL, "filelists.xml.gz") < 0)
		return -1;
	curl_easy_cleanup(curl);

	set = razor_set_create_from_yum();
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
	struct razor_transaction *trans;

	set = razor_set_open(repo_filename);
	upstream = razor_set_open(rawhide_repo_filename);
	if (set == NULL || upstream == NULL)
		return 1;
	trans = razor_transaction_create(set, upstream, argc, argv, 0, NULL);
	razor_transaction_describe(trans);
	if (trans->errors)
		return 1;

	set = razor_transaction_run(trans);
	razor_transaction_destroy(trans);
	razor_set_write(set, updated_repo_filename);
	razor_set_destroy(set);
	razor_set_destroy(upstream);
	printf("wrote system-updated.repo\n");

	return 0;
}

static int
command_remove(int argc, const char *argv[])
{
	struct razor_set *set;
	struct razor_transaction *trans;

	set = razor_set_open(repo_filename);
	if (set == NULL)
		return 1;
	trans = razor_transaction_create(set, NULL, 0, NULL, argc, argv);
	razor_transaction_describe(trans);
	if (trans->errors)
		return 1;

	set = razor_transaction_run(trans);
	razor_transaction_destroy(trans);
	razor_set_write(set, updated_repo_filename);
	razor_set_destroy(set);
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

static int
command_import_rpms(int argc, const char *argv[])
{
	DIR *dir;
	struct dirent *de;
	struct razor_importer *importer;
	struct razor_set *set;
	struct razor_rpm *rpm;
	int len;
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

	importer = razor_importer_new();

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
	}

	if (de != NULL) {
		razor_importer_destroy(importer);
		return -1;
	}

	set = razor_importer_finish(importer);

	razor_set_write(set, repo_filename);
	razor_set_destroy(set);
	printf("wrote %s\n", repo_filename);

	return 0;
}

static struct razor_set *
create_set_from_rpms(int argc, const char *argv[])
{
	struct razor_importer *importer;
	struct razor_rpm *rpm;
	int i;

	importer = razor_importer_new();
	for (i = 0; i < argc; i++) {
		rpm = razor_rpm_open(argv[i]);
		if (rpm == NULL) {
			fprintf(stderr,
				"failed to open rpm \"%s\"\n", argv[i]);
			continue;
		}
		if (razor_importer_add_rpm(importer, rpm)) {
			fprintf(stderr, "couldn't import %s\n", argv[i]);
			break;
		}
		razor_rpm_close(rpm);
	}

	return razor_importer_finish(importer);
}

static char **
list_packages(int count, struct razor_set *set)
{
	struct razor_package_iterator *pi;
	struct razor_package *package;
	const char *name, *version;
	char **packages;
	int i;

	packages = malloc(count * sizeof *packages);
	pi = razor_package_iterator_create(set);
	i = 0;
	while (razor_package_iterator_next(pi, &package, &name, &version))
		packages[i++] = strdup(name);
	razor_package_iterator_destroy(pi);

	return packages;
}

static int
command_install(int argc, const char *argv[])
{
	struct razor_set *system, *upstream, *next;
	struct razor_transaction *trans;
	struct razor_rpm *rpm;
	const char *filename;
	char path[PATH_MAX], new_path[PATH_MAX], **packages;
	int i;

	upstream = create_set_from_rpms(argc, argv);
	snprintf(path, sizeof path,
		 "%s%s/%s", root, razor_root_path, system_repo_filename);
	system = razor_set_open(path);
	if (system == NULL) {
		fprintf(stderr, "couldn't open system package database\n");
		return -1;
	}

	packages = list_packages(argc, upstream);
	trans = razor_transaction_create(system, upstream,
					 argc, (const char **)packages,
					 0, NULL);
	free(packages);
	razor_transaction_describe(trans);
	if (trans->errors)
		return 1;

	/* FIXME: Use _finish() convention here?  That is, a function
	 * that starts the computation and returns the result while
	 * destroying the transaction.  Nice for transient objects
	 * such as the merger and the importer.  Should we do that for
	 * transactions too, that is, razor_transaction_finish()? */
	next = razor_transaction_run(trans);
	razor_transaction_destroy(trans);

	/* FIXME: Need razor_set_write_to_fd() so we can open it excl
	 * up front here or fail if it already exists. */
	snprintf(new_path, sizeof new_path,
		 "%s%s/%s", root, razor_root_path, next_repo_filename);
	razor_set_write(next, path);

	razor_set_destroy(next);
	razor_set_destroy(system);
	razor_set_destroy(upstream);

	printf("wrote %s\n", new_path);

	for (i = 0; i < argc; i++) {
		filename = argv[i];
		rpm = razor_rpm_open(argv[i]);
		if (rpm == NULL) {
			fprintf(stderr, "failed to open rpm %s\n", filename);
			return -1;
		}
		if (razor_rpm_install(rpm, root) < 0) {
			fprintf(stderr,
				"failed to install rpm %s\n", filename);
			return -1;
		}
		razor_rpm_close(rpm);
	}	

	/* Make it so. */
	rename(new_path, path);
	printf("renamed %s to %s\n", new_path, path);

	return 0;
}

static int
command_init(int argc, const char *argv[])
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

	if (razor_create_dir(root, razor_root_path) < 0) {
		fprintf(stderr, "could not create %s%s\n",
			root, razor_root_path);
		return -1;
	}

	set = razor_set_create();
	snprintf(path, sizeof path, "%s%s/%s",
		 root, razor_root_path, system_repo_filename);
	if (razor_set_write(set, path) < 0) {
		fprintf(stderr, "could not write initial package set\n");
		return -1;
	}
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
	{ "validate", "validate a package set", command_validate },
	{ "update", "update all or specified packages", command_update },
	{ "remove", "remove specified packages", command_remove },
	{ "diff", "show diff between two package sets", command_diff },
	{ "install", "install rpm", command_install },
	{ "init", "init razor root", command_init }
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
