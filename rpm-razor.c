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
#include <string.h>
#include <stdio.h>
#include "razor.h"

enum option_type {
	OPTION_LAST,
	OPTION_GROUP,
	OPTION_BOOL,
	OPTION_STRING
};

struct option {
	enum option_type type;
	const char *name;
	char short_name;
	const char *arg_name;
	const char *description;
	void *data;
};

static int option_all, option_whatrequires, option_whatprovides;


static const struct option query_options[] = {
	{ OPTION_BOOL, "configfiles", 'c', NULL, "list all configuration files", NULL },
	{ OPTION_BOOL, "docfiles", 'd', NULL, "list all documentation files", NULL },
	{ OPTION_BOOL, "dump", 0, NULL, "dump basic file information", NULL },
	{ OPTION_BOOL, "list", 0, NULL, "list files in package", NULL },
	{ OPTION_STRING, "queryformat", 0, "QUERYFORMAT", "use the following query format", NULL },
	{ OPTION_BOOL, "state", 's', NULL, "display the states of the listed files", NULL },
	{ OPTION_BOOL, "all", 'a', NULL, "query/verify all packages", &option_all },
	{ OPTION_BOOL, "file", 'f', NULL, "query/verify package(s) owning file", NULL },
	{ OPTION_BOOL, "group", 'g', NULL, "query/verify package(s) in group", NULL },
	{ OPTION_BOOL, "package", 'p', NULL, "query/verify a package file", NULL },
	{ OPTION_BOOL, "ftswalk", 'W', NULL, "query/verify package(s) from TOP file tree walk", NULL },
	{ OPTION_BOOL, "pkgid", 0, NULL, "query/verify package(s) with package identifier", NULL },
	{ OPTION_BOOL, "hdrid", 0, NULL, "query/verify package(s) with header identifier", NULL },
	{ OPTION_BOOL, "fileid", 0, NULL, "query/verify package(s) with file identifier", NULL },
	{ OPTION_BOOL, "specfile", 0, NULL, "query a spec file", NULL, },
	{ OPTION_BOOL, "triggeredby", 0, NULL, "query the package(s) triggered by the package", NULL },
	{ OPTION_BOOL, "whatrequires", 0, NULL, "query/verify the package(s) which require a dependency", &option_whatrequires },
	{ OPTION_BOOL, "whatprovides", 0, NULL, "query/verify the package(s) which provide a dependency", &option_whatprovides },
	{ OPTION_BOOL, "nomanifest", 0, NULL, "do not process non-package files as manifests", NULL },
	{ }
};

static const struct option verify_options[] = {
	{ OPTION_BOOL, "nomd5", 0, NULL, "don't verify MD5 digest of files", NULL },
	{ OPTION_BOOL, "nofiles", 0, NULL, "don't verify files in package", NULL },
	{ OPTION_BOOL, "nodeps", 0, NULL, "don't verify package dependencies", NULL },
	{ OPTION_BOOL, "noscript", 0, NULL, "don't execute verify script(s)", NULL, },
	{ OPTION_BOOL, "all", 'a', NULL, "query/verify all packages", NULL },
	{ OPTION_BOOL, "file", 'f', NULL, "query/verify package(s) owning file", NULL },
	{ OPTION_BOOL, "group", 'g', NULL, "query/verify package(s) in group", NULL },
	{ OPTION_BOOL, "package", 'p', NULL, "query/verify a package file", NULL },
	{ OPTION_BOOL, "ftswalk", 'W', NULL, "query/verify package(s) from TOP file tree walk", NULL },
	{ OPTION_BOOL, "pkgid", 0, NULL, "query/verify package(s) with package identifier", NULL },
	{ OPTION_BOOL, "hdrid", 0, NULL, "query/verify package(s) with header identifier", NULL },
	{ OPTION_BOOL, "fileid", 0, NULL, "query/verify package(s) with file identifier", NULL },
	{ OPTION_BOOL, "specfile", 0, NULL, "query a spec file", NULL },
	{ OPTION_BOOL, "triggeredby", 0, NULL, "query the package(s) triggered by the package", NULL },
	{ OPTION_BOOL, "whatrequires", 0, NULL, "query/verify the package(s) which require a dependency", &option_whatrequires },
	{ OPTION_BOOL, "whatprovides", 0, NULL, "query/verify the package(s) which provide a dependency", &option_whatprovides },
	{ OPTION_BOOL, "nomanifest", 0, NULL, "do not process non-package files as manifests", NULL },
	{ }
};

static const struct option ftw_options[] = {
	{ OPTION_BOOL, "comfollow", 0, NULL, "FTS_COMFOLLOW: follow command line symlinks", NULL },
	{ OPTION_BOOL, "logical", 0, NULL, "FTS_LOGICAL: logical walk", NULL },
	{ OPTION_BOOL, "nochdir", 0, NULL, "FTS_NOCHDIR: don't change directories", NULL },
	{ OPTION_BOOL, "nostat", 0, NULL, "FTS_NOSTAT: don't get stat info", NULL },
	{ OPTION_BOOL, "physical", 0, NULL, "FTS_PHYSICAL: physical walk", NULL },
	{ OPTION_BOOL, "seedot", 0, NULL, "FTS_SEEDOT: return dot and dot-dot", NULL },
	{ OPTION_BOOL, "xdev", 0, NULL, "FTS_XDEV: don't cross devices", NULL },
	{ OPTION_BOOL, "whiteout", 0, NULL, "FTS_WHITEOUT: return whiteout information", NULL },
	{ }
};

static const struct option signature_options[] = {
	{ OPTION_BOOL, "addsign", 0, NULL, "sign package(s) (identical to --resign)", NULL, },
	{ OPTION_BOOL, "checksig", 'K', NULL, "verify package signature(s)", NULL, },
	{ OPTION_BOOL, "delsign", 0, NULL, "delete package signatures", NULL, },
	{ OPTION_BOOL, "import", 0, NULL, "import an armored public key", NULL, },
	{ OPTION_BOOL, "resign", 0, NULL, "sign package(s) (identical to --addsign)", NULL, },
	{ OPTION_BOOL, "nodigest", 0, NULL, "don't verify package digest(s)", NULL, },
	{ OPTION_BOOL, "nosignature", 0, NULL, "don't verify package signature(s)", NULL },
	{ }
};

static const struct option database_options[] = {
	{ OPTION_BOOL, "initdb", 0, NULL, "initialize database", NULL },
	{ OPTION_BOOL, "rebuilddb", 0, NULL, "rebuild database inverted lists from installed package headers", NULL },
	{ }
};

static int option_erase, option_install, option_upgrade;

static const struct option install_options[] = {
	{ OPTION_BOOL, "aid", 0, NULL, "add suggested packages to transaction", NULL, },
	{ OPTION_BOOL, "allfiles", 0, NULL, "install all files, even configurations which might otherwise be skipped", NULL, },
	{ OPTION_BOOL, "allmatches", 0, NULL, "remove all packages which match <package> (normally an error is generated if <package> specified multiple packages)", NULL, },
	{ OPTION_BOOL, "badreloc", 0, NULL, "relocate files in non-relocatable package", NULL },
	{ OPTION_BOOL, "erase", 'e', "<package>", "erase (uninstall) package", &option_erase },
	{ OPTION_BOOL, "excludedocs", 0, NULL, "do not install documentation", NULL, },
	{ OPTION_BOOL, "excludepath", 0, "<path>", "skip files with leading component <path> ", NULL, },
	{ OPTION_BOOL, "fileconflicts", 0, NULL, "detect file conflicts between packages", NULL, },
	{ OPTION_BOOL, "force", 0, NULL, "short hand for --replacepkgs --replacefiles", NULL },
	{ OPTION_BOOL, "freshen", 'F', "<packagefile>+", "upgrade package(s) if already installed", NULL },
	{ OPTION_BOOL, "hash", 'h', NULL, "print hash marks as package installs (good with -v)", NULL },
	{ OPTION_BOOL, "ignorearch", 0, NULL, "don't verify package architecture", NULL, },
	{ OPTION_BOOL, "ignoreos", 0, NULL, "don't verify package operating system", NULL, },
	{ OPTION_BOOL, "ignoresize", 0, NULL, "don't check disk space before installing", NULL },
	{ OPTION_BOOL, "install", 'i', NULL, "install package(s)", &option_install },
	{ OPTION_BOOL, "justdb", 0, NULL, "update the database, but do not modify the filesystem", NULL, },
	{ OPTION_BOOL, "nodeps", 0, NULL, "do not verify package dependencies", NULL, },
	{ OPTION_BOOL, "nomd5", 0, NULL, "don't verify MD5 digest of files", NULL, },
	{ OPTION_BOOL, "nocontexts", 0, NULL, "don't install file security contexts", NULL, },
	{ OPTION_BOOL, "noorder", 0, NULL, "do not reorder package installation to satisfy dependencies", NULL, },
	{ OPTION_BOOL, "nosuggest", 0, NULL, "do not suggest missing dependency resolution(s)", NULL, },
	{ OPTION_BOOL, "noscripts", 0, NULL, "do not execute package scriptlet(s)", NULL, },
	{ OPTION_BOOL, "notriggers", 0, NULL, "do not execute any scriptlet(s) triggered by this package", NULL, },
	{ OPTION_BOOL, "oldpackage", 0, NULL, "upgrade to an old version of the package (--force on upgrades does this automatically)", NULL },
	{ OPTION_BOOL, "percent", 0, NULL, "print percentages as package installs", NULL, },
	{ OPTION_STRING, "prefix", 0, "<dir>", "relocate the package to <dir>, if relocatable", NULL, },
	{ OPTION_STRING, "relocate", 0, "<old>=<new>", "relocate files from path <old> to <new>", NULL, },
	{ OPTION_BOOL, "repackage", 0, NULL, "save erased package files by repackaging", NULL, },
	{ OPTION_BOOL, "replacefiles", 0, NULL, "ignore file conflicts between packages", NULL, },
	{ OPTION_BOOL, "replacepkgs", 0, NULL, "reinstall if the package is already present", NULL, },
	{ OPTION_BOOL, "test", 0, NULL, "don't install, but tell if it would work or not", NULL },
	{ OPTION_BOOL, "upgrade", 'U', "<packagefile>+", "upgrade package(s)", &option_upgrade },
	{ }
};

static int option_version;

static const struct option common_options[] = {
	{ OPTION_STRING, "define", 'D', "MACRO EXPR", "define MACRO with value EXPR", NULL, },
	{ OPTION_STRING, "eval", 'E', "EXPR", "print macro expansion of EXPR", NULL },
	{ OPTION_STRING, "macros", 0, "<FILE:...>", "read <FILE:...> instead of default file(s)", NULL },
	{ OPTION_BOOL, "nodigest", 0, NULL, "don't verify package digest(s)", NULL, },
	{ OPTION_BOOL, "nosignature", 0, NULL, "don't verify package signature(s)", NULL, },
	{ OPTION_STRING, "rcfile", 0, "<FILE:...>", "read <FILE:...> instead of default file(s)", NULL },
	{ OPTION_STRING, "root", 'r', "ROOT", "use ROOT as top level directory (default: \"/\")", NULL },
	{ OPTION_BOOL, "querytags", 0, NULL, "display known query tags", NULL, },
	{ OPTION_BOOL, "showrc", 0, NULL, "display final rpmrc and macro configuration", NULL, },
	{ OPTION_BOOL, "quiet", 0, NULL, "provide less detailed output", NULL },
	{ OPTION_BOOL, "verbose", 'v', NULL, "provide more detailed output", NULL },
	{ OPTION_BOOL, "version", 0, NULL, "print the version of rpm being used", &option_version },
	{ }
};

static int option_conflicts, option_obsoletes, option_requires, option_provides;

static const struct option alias_options[] = {
	{ OPTION_BOOL, "scripts", 0, NULL, "list install/erase scriptlets from package(s)", NULL, },
	{ OPTION_BOOL, "setperms", 0, NULL, "set permissions of files in a package", NULL, },
	{ OPTION_BOOL, "setugids", 0, NULL, "set user/group ownership of files in a package", NULL, },
	{ OPTION_BOOL, "conflicts", 0, NULL, "list capabilities this package conflicts with", &option_conflicts, },
	{ OPTION_BOOL, "obsoletes", 0, NULL, "list other packages removed by installing this package", &option_obsoletes, },
	{ OPTION_BOOL, "provides", 0, NULL, "list capabilities that this package provides", &option_provides, },
	{ OPTION_BOOL, "requires", 0, NULL, "list capabilities required by package(s)", &option_requires, },
	{ OPTION_BOOL, "info", 0, NULL, "list descriptive information from package(s)", NULL, },
	{ OPTION_BOOL, "changelog", 0, NULL, "list change logs for this package", NULL, },
	{ OPTION_BOOL, "xml", 0, NULL, "list metadata in xml", NULL, },
	{ OPTION_BOOL, "triggers", 0, NULL, "list trigger scriptlets from package(s)", NULL, },
	{ OPTION_BOOL, "last", 0, NULL, "list package(s) by install time, most recent first", NULL, },
	{ OPTION_BOOL, "dupes", 0, NULL, "list duplicated packages", NULL, },
	{ OPTION_BOOL, "filesbypkg", 0, NULL, "list all files from each package", NULL, },
	{ OPTION_BOOL, "fileclass", 0, NULL, "list file names with classes", NULL, },
	{ OPTION_BOOL, "filecolor", 0, NULL, "list file names with colors", NULL, },
	{ OPTION_BOOL, "filecontext", 0, NULL, "list file names with security context from header", NULL, },
	{ OPTION_BOOL, "fscontext", 0, NULL, "list file names with security context from file system", NULL, },
	{ OPTION_BOOL, "recontext", 0, NULL, "list file names with security context from policy RE", NULL, },
	{ OPTION_BOOL, "fileprovide", 0, NULL, "list file names with provides", NULL, },
	{ OPTION_BOOL, "filerequire", 0, NULL, "list file names with requires", NULL, },
	{ OPTION_BOOL, "redhatprovides", 0, NULL, "find package name that contains a provided capability (needs rpmdb-redhat package installed)", NULL, },
	{ OPTION_BOOL, "redhatrequires", 0, NULL, "find package name that contains a required capability (needs rpmdb-redhat package installed)", NULL, },
	{ OPTION_STRING, "buildpolicy", 0, "<policy>", "set buildroot <policy> (e.g. compress man pages)", NULL, },
	{ OPTION_BOOL, "with", 0, "<option>", "enable configure <option> for build", NULL, },
	{ OPTION_BOOL, "without", 0, "<option>", "disable configure <option> for build", NULL },
	{ }
};

static int option_help, option_usage;

static const struct option help_options[] = {
	{ OPTION_BOOL, "help", '?', NULL, "Show this help message", &option_help },
	{ OPTION_BOOL, "usage", 0, NULL, "Display brief usage message", &option_usage},
	{ }
};

static int option_query, option_verify;

static const struct option rpm_options[] = {
	{ OPTION_BOOL, "query", 'q', NULL, "Query rpm database", &option_query },
	{ OPTION_BOOL, "verify", 'V', NULL, "Verify rpm database", &option_verify },
	{ OPTION_GROUP, NULL, 0, NULL, "Query options (with -q or --query):", &query_options },
	{ OPTION_GROUP, NULL, 0, NULL, "Verify options (with -V or --verify):", &verify_options },
	{ OPTION_GROUP, NULL, 0, NULL, "File tree walk options (with --ftswalk):", &ftw_options },
	{ OPTION_GROUP, NULL, 0, NULL, "Signature options:", &signature_options },
	{ OPTION_GROUP, NULL, 0, NULL, "Database options:", &database_options },
	{ OPTION_GROUP, NULL, 0, NULL, "Install/Upgrade/Erase options:", &install_options },
	{ OPTION_GROUP, NULL, 0, NULL, "Common options for all rpm modes and executables:", &common_options },
	{ OPTION_GROUP, NULL, 0, NULL, "Options implemented via popt alias/exec:", &alias_options },
	{ OPTION_GROUP, NULL, 0, NULL, "Help options", &help_options },
	{ }
};

static const char system_repo_filename[] = "system.repo";
static const char *repo_filename = system_repo_filename;

static struct razor_property *
add_property_packages(struct razor_set *set, 
		      struct razor_package_query *query,
		      const char *ref_name,
		      const char *ref_version,
		      enum razor_property_type ref_type)
{
	struct razor_property *property;
	struct razor_property_iterator *pi;
	struct razor_package_iterator *pkgi;
	const char *name, *version;
	enum razor_property_type type;
	enum razor_version_relation relation;

	pi = razor_property_iterator_create(set, NULL);
	while (razor_property_iterator_next(pi, &property, &name,
					    &relation, &version, &type)) {
		if (strcmp(ref_name, name) != 0)
			continue;
		if (ref_version && relation == RAZOR_VERSION_EQUAL &&
		    strcmp(ref_version, version) != 0)
			continue;
		if (ref_type != type)
			continue;

		pkgi = razor_package_iterator_create_for_property(set,
								  property);
		razor_package_query_add_iterator(query, pkgi);
		razor_package_iterator_destroy(pkgi);
	}
	razor_property_iterator_destroy(pi);

	return property;
}

static int
strcmpp(const void *p1, const void *p2)
{
	return strcmp(*(char * const *) p1, *(char * const *) p2);
}

static void
add_command_line_packages(struct razor_set *set,
			  struct razor_package_query *query,
			  int argc, const char **argv)
{
	struct razor_package *package;
	struct razor_package_iterator *pi;
	const char *name, *version, *arch;
	int i, cmp;

	qsort(argv, argc, sizeof(*argv), strcmpp);
	i = 0;

	pi = razor_package_iterator_create(set);

	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		while (cmp = strcmp(argv[i], name), cmp < 0 && i < argc) {
			printf("package %s is not installed\n", argv[i]);
			i++;
		}

		if (cmp == 0) {
			razor_package_query_add_package(query, package);
			i++;
		}
	}

	razor_package_iterator_destroy(pi);
}

static void
print_package_properties(struct razor_set *set,
			 struct razor_package *package,
			 enum razor_property_type ref_type)
{
	struct razor_property *property;
	struct razor_property_iterator *pi;
	const char *name, *version;
	enum razor_property_type type;
	enum razor_version_relation relation;

	pi = razor_property_iterator_create(set, package);
	while (razor_property_iterator_next(pi, &property,
					    &name, &relation, &version,
					    &type)) {
		if (type != ref_type)
			continue;
		if (version[0] == '\0')
			printf("%s\n", name);
		else
			printf("%s %s %s\n", name,
			       razor_version_relations[relation], version);
	}
	razor_property_iterator_destroy(pi);
}

static void
command_query(int argc, const char *argv[])
{
	struct razor_set *set;
	struct razor_package_iterator *pi;
	struct razor_package *package;
	struct razor_package_query *query;
	const char *name, *version, *arch;

	set = razor_set_open(repo_filename);

	if (option_all + option_whatprovides + option_whatrequires > 1) {
		printf("only one type of query/verify "
		       "may be performed at a time\n");
		exit(1);
	}

	query = razor_package_query_create(set);
	if (option_all) {
		pi = razor_package_iterator_create(set);
		razor_package_query_add_iterator(query, pi);
		razor_package_iterator_destroy(pi);
	} else if (option_whatrequires) {
		add_property_packages(set, query,
				      argv[0], NULL, RAZOR_PROPERTY_REQUIRES);
	} else if (option_whatprovides) {
		add_property_packages(set, query,
				      argv[0], NULL, RAZOR_PROPERTY_PROVIDES);
	} else if (argc > 0) {
		add_command_line_packages(set, query, argc, argv);
	} else {
		printf("no arguments given for query\n");
		exit(1);
	}

	pi = razor_package_query_finish(query);

	while (razor_package_iterator_next(pi, &package,
					   &name, &version, &arch)) {
		if (option_conflicts)
			print_package_properties(set, package,
						 RAZOR_PROPERTY_CONFLICTS);
		if (option_obsoletes)
			print_package_properties(set, package,
						 RAZOR_PROPERTY_OBSOLETES);
		if (option_requires)
			print_package_properties(set, package,
						 RAZOR_PROPERTY_REQUIRES);
		if (option_provides)
			print_package_properties(set, package,
						 RAZOR_PROPERTY_PROVIDES);
		if (!option_conflicts && !option_obsoletes &&
		    !option_requires && !option_provides)
			printf("%s-%s.%s\n", name, version, arch);
	}

	razor_package_iterator_destroy(pi);

	razor_set_destroy(set);

	return;
}

static void
command_verify(int argc, const char *argv[])
{
	if (argc == 0) {
		printf("no arguments given for verify\n");
		exit(1);
	}

	printf("command verify - not implemented\n");
}

static void
command_erase(int argc, const char *argv[])
{
	if (argc == 0) {
		printf("no packages given for erase\n");
		exit(1);
	}

	printf("command erase - not implemented\n");
}

static void
command_install(int argc, const char *argv[])
{
	if (argc == 0) {
		printf("no packages given for install\n");
		exit(1);
	}

	printf("command install - not implemented\n");
}

static void
command_update(int argc, const char *argv[])
{
	if (argc == 0) {
		printf("no packages given for update\n");
		exit(1);
	}

	printf("command update - not implemented\n");
}

static const struct option *
find_option(const struct option *options, const char *s)
{
	const struct option *o;
	int i;

	for (i = 0; options[i].type != OPTION_LAST; i++) {
		switch (options[i].type) {
		case OPTION_GROUP:
			o = find_option(options[i].data, s);
			if (o != NULL)
				return o;
			break;

		case OPTION_BOOL:
		case OPTION_STRING:
			if (s[0] == '-' &&
			    s[1] == options[i].short_name && s[2] == '\0')
				return &options[i];
			if (s[0] == '-' && s[1] == '-' &&
			    strcmp(options[i].name, s + 2) == 0)
				return &options[i];
			break;

		case OPTION_LAST:
			break;
		}
	}

	return NULL;
}

static int
parse_options(const struct option *options, int argc, const char **argv)
{
	const struct option *o;
	int i, j;

	/* FIXME: Bundling... rpm -Uvh must work :) */

	for (i = 1, j = 0; i < argc; i++) {
		if (argv[i][0] != '-') {
			argv[j++] = argv[i];
			continue;
		}
		o = find_option(options, argv[i]);
		if (o == NULL) {
			printf("unknown option: \"%s\"\n", argv[i]);
			continue;
		}
		if (o->data == NULL) {
			printf("option \"%s\" not supported\n", argv[i]);
			continue;
		}
		switch (o->type) {
		case OPTION_BOOL:
			*(int *) o->data = 1;
			break;

		case OPTION_STRING:
			*(const char **) o->data =
				argv[i] + strlen(o->name) + 3;
			break;

		case OPTION_LAST:
		case OPTION_GROUP:
			/* Shouldn't happen. */
			break;
		}
	}

	return j;
}

static void
print_options_help(const struct option *options)
{
	int i;

	for (i = 0; options[i].type != OPTION_LAST; i++) {
		switch (options[i].type) {
		case OPTION_GROUP:
			printf("%s\n", options[i].description);
			print_options_help(options[i].data);
			printf("\n");
			break;

		case OPTION_BOOL:
		case OPTION_STRING:
			printf("  ");
			if (options[i].short_name)
				printf("-%c", options[i].short_name);
			if (options[i].short_name && options[i].name)
				printf(", ");
			if (options[i].name)
				printf("--%s", options[i].name);
			if (options[i].arg_name)
				printf("=%s", options[i].arg_name);
			if (options[i].description)
				printf("\t\t%s", options[i].description);
			printf("\n");
			break;

		case OPTION_LAST:
			break;
		}
	}
}

static void
print_options_usage(const struct option *options)
{
	int i;

	for (i = 0; options[i].type != OPTION_LAST; i++) {
		switch (options[i].type) {
		case OPTION_GROUP:
			print_options_usage(options[i].data);
			break;

		case OPTION_BOOL:
			printf("[");
			if (options[i].short_name)
				printf("-%c", options[i].short_name);
			if (options[i].short_name && options[i].name)
				printf("|");
			if (options[i].name)
				printf("--%s", options[i].name);
			printf("] ");
			break;

		case OPTION_STRING:
			printf("[");
			if (options[i].short_name)
				printf("-%c", options[i].short_name);
			if (options[i].short_name && options[i].name)
				printf("|");
			if (options[i].name)
				printf("--%s", options[i].name);
			if (options[i].arg_name)
				printf("=%s", options[i].arg_name);
			printf("] ");
			break;


			break;

		case OPTION_LAST:
			break;
		}
	}
}

int
main(int argc, const char *argv[])
{
	argc = parse_options(rpm_options, argc, argv);

	if (option_version) {
		printf("razor rpm version hoopla.\n");
		exit(0);
	}

	if (option_help) {
		printf("Usage: rpm [OPTION...]\n");
		print_options_help(rpm_options);
		exit(0);
	}

	if (option_usage) {
		printf("Usage: rpm [OPTION...]\n");
		print_options_usage(rpm_options);
		printf("\n");
		exit(0);
	}

	if (option_query + option_verify +
	    option_erase + option_install + option_upgrade > 1) {
		printf("specify only one of query, verify, erase, install "
		       "or upgrade\n");
		exit(1);
	}
	    
	if (option_query) {
		command_query(argc, argv);
	} else if (option_verify) {
		command_verify(argc, argv);
	} else if (option_erase) {
		command_erase(argc, argv);
	} else if (option_install) {
		command_install(argc, argv);
	} else if (option_upgrade) {
		command_update(argc, argv);
	} else {
		print_options_usage(rpm_options);
		printf("\n");
		exit(0);
	}

	return 0;
}
