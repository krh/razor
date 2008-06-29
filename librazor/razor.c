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

#define _GNU_SOURCE

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <fnmatch.h>
#include <assert.h>

#include "razor-internal.h"
#include "razor.h"

void *
zalloc(size_t size)
{
	void *p;

	p = malloc(size);
	memset(p, 0, size);

	return p;
}

struct razor_set_section razor_sections[] = {
	{ RAZOR_STRING_POOL,	offsetof(struct razor_set, string_pool) },
	{ RAZOR_PACKAGES,	offsetof(struct razor_set, packages) },
	{ RAZOR_PROPERTIES,	offsetof(struct razor_set, properties) },
	{ RAZOR_PACKAGE_POOL,	offsetof(struct razor_set, package_pool) },
	{ RAZOR_PROPERTY_POOL,	offsetof(struct razor_set, property_pool) },
};

struct razor_set_section razor_files_sections[] = {
	{ RAZOR_FILES,			offsetof(struct razor_set, files) },
	{ RAZOR_FILE_POOL,		offsetof(struct razor_set, file_pool) },
	{ RAZOR_FILE_STRING_POOL,	offsetof(struct razor_set, file_string_pool) },
};

struct razor_set_section razor_details_sections[] = {
	{ RAZOR_DETAILS_STRING_POOL,	offsetof(struct razor_set, details_string_pool) },
};

RAZOR_EXPORT struct razor_set *
razor_set_create(void)
{
	struct razor_set *set;
	struct razor_entry *e;
	char *empty;

	set = zalloc(sizeof *set);

	e = array_add(&set->files, sizeof *e);
	empty = array_add(&set->string_pool, 1);
	*empty = '\0';
	e->name = 0;
	e->flags = RAZOR_ENTRY_LAST;
	e->start = 0;
	list_set_empty(&e->packages);

	return set;
}

RAZOR_EXPORT struct razor_set *
razor_set_open(const char *filename)
{
	struct razor_set *set;
	struct razor_set_section *s;
	struct stat stat;
	struct array *array;
	int fd;

	set = zalloc(sizeof *set);
	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return NULL;
	set->header = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (set->header == MAP_FAILED) {
		free(set);
		return NULL;
	}

	for (s = set->header->sections; ~s->type; s++) {
		if (s->type >= ARRAY_SIZE(razor_sections))
			continue;
		if (s->type != razor_sections[s->type].type)
			continue;
		array = (void *) set + razor_sections[s->type].offset;
		array->data = (void *) set->header + s->offset;
		array->size = s->size;
		array->alloc = s->size;
	}
	close(fd);

	return set;
}

RAZOR_EXPORT int
razor_set_open_details(struct razor_set *set, const char *filename)
{
	struct razor_set_section *s;
	struct stat stat;
	struct array *array;
	int fd;

	assert (set != NULL);
	assert (filename != NULL);

	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return -1;
	set->details_header = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (set->details_header == MAP_FAILED)
		return -1;

	for (s = set->details_header->sections; ~s->type; s++) {
		if (s->type >= ARRAY_SIZE(razor_details_sections))
			continue;
		if (s->type != razor_details_sections[s->type].type)
			continue;
		array = (void *) set + razor_details_sections[s->type].offset;
		array->data = (void *) set->details_header + s->offset;
		array->size = s->size;
		array->alloc = s->size;
	}
	close(fd);

	return 0;
}

RAZOR_EXPORT int
razor_set_open_files(struct razor_set *set, const char *filename)
{
	struct razor_set_section *s;
	struct stat stat;
	struct array *array;
	int fd;

	assert (set != NULL);
	assert (filename != NULL);

	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return -1;
	set->files_header = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (set->files_header == MAP_FAILED)
		return -1;

	for (s = set->files_header->sections; ~s->type; s++) {
		if (s->type >= ARRAY_SIZE(razor_files_sections))
			continue;
		if (s->type != razor_files_sections[s->type].type)
			continue;
		array = (void *) set + razor_files_sections[s->type].offset;
		array->data = (void *) set->files_header + s->offset;
		array->size = s->size;
		array->alloc = s->size;
	}
	close(fd);

	return 0;
}

RAZOR_EXPORT void
razor_set_destroy(struct razor_set *set)
{
	unsigned int size;
	struct array *a;
	int i;

	assert (set != NULL);

	if (set->header) {
		for (i = 0; set->header->sections[i].type; i++)
			;
		size = set->header->sections[i].type;
		munmap(set->header, size);
	} else {
		for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
			a = (void *) set + razor_sections[i].offset;
			free(a->data);
		}
	}

	if (set->details_header) {
		for (i = 0; set->details_header->sections[i].type; i++)
			;
		size = set->details_header->sections[i].type;
		munmap(set->details_header, size);
	} else {
		for (i = 0; i < ARRAY_SIZE(razor_details_sections); i++) {
			a = (void *) set + razor_details_sections[i].offset;
			free(a->data);
		}
	}

	if (set->files_header) {
		for (i = 0; set->files_header->sections[i].type; i++)
			;
		size = set->files_header->sections[i].type;
		munmap(set->files_header, size);
	} else {
		for (i = 0; i < ARRAY_SIZE(razor_files_sections); i++) {
			a = (void *) set + razor_files_sections[i].offset;
			free(a->data);
		}
	}

	free(set);
}

static int
razor_set_write_sections_to_fd(struct razor_set *set, int fd, int magic,
			       struct razor_set_section *sections,
			       size_t array_size)
{
	char data[4096];
	struct razor_set_header *header = (struct razor_set_header *) data;
	struct array *a;
	uint32_t offset;
	int i;

	memset(data, 0, sizeof data);
	header->magic = magic;
	header->version = RAZOR_VERSION;
	offset = sizeof data;

	for (i = 0; i < array_size; i++) {
		if (sections[i].type != i)
			continue;
		a = (void *) set + sections[i].offset;
		header->sections[i].type = i;
		header->sections[i].offset = offset;
		header->sections[i].size = a->size;
		offset += ALIGN(a->size, 4096);
	}

	header->sections[i].type = ~0;
	header->sections[i].offset = 0;
	header->sections[i].size = 0;

	razor_write(fd, data, sizeof data);
	memset(data, 0, sizeof data);
	for (i = 0; i < array_size; i++) {
		if (sections[i].type != i)
			continue;
		a = (void *) set + sections[i].offset;
		razor_write(fd, a->data, a->size);
		razor_write(fd, data, ALIGN(a->size, 4096) - a->size);
	}

	return 0;
}

RAZOR_EXPORT int
razor_set_write_to_fd(struct razor_set *set, int fd,
		      enum razor_repo_file_type type)
{
	switch (type) {
	case RAZOR_REPO_FILE_MAIN:
		return razor_set_write_sections_to_fd(set, fd, RAZOR_MAGIC,
						      razor_sections,
						      ARRAY_SIZE(razor_sections));

	case RAZOR_REPO_FILE_DETAILS:
		return razor_set_write_sections_to_fd(set, fd, RAZOR_DETAILS_MAGIC,
						      razor_details_sections,
						      ARRAY_SIZE(razor_details_sections));
	case RAZOR_REPO_FILE_FILES:
		return razor_set_write_sections_to_fd(set, fd, RAZOR_FILES_MAGIC,
						      razor_files_sections,
						      ARRAY_SIZE(razor_files_sections));
	default:
		return -1;
	}
}

RAZOR_EXPORT int
razor_set_write(struct razor_set *set, const char *filename,
		enum razor_repo_file_type type)
{
	int fd, status;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	status = razor_set_write_to_fd(set, fd, type);
	if (status) {
	    close(fd);
	    return status;
	}

	return close(fd);
}

RAZOR_EXPORT void
razor_build_evr(char *evr_buf, int size, const char *epoch,
		const char *version, const char *release)
{
	int len;

	if (!version || !*version) {
		*evr_buf = '\0';
		return;
	}

	if (epoch && *epoch && strcmp(epoch, "0") != 0) {
		len = snprintf(evr_buf, size, "%s:", epoch);
		evr_buf += len;
		size -= len;
	}
	len = snprintf(evr_buf, size, "%s", version);
	evr_buf += len;
	size -= len;
	if (release && *release)
		snprintf(evr_buf, size, "-%s", release);
}

RAZOR_EXPORT int
razor_versioncmp(const char *s1, const char *s2)
{
	const char *p1, *p2;
	long n1, n2;
	int res;

	assert (s1 != NULL);
	assert (s2 != NULL);

	n1 = strtol(s1, (char **) &p1, 10);
	n2 = strtol(s2, (char **) &p2, 10);

	/* Epoch; if one but not the other has an epoch set, default
	 * the epoch-less version to 0. */
	res = (*p1 == ':') - (*p2 == ':');
	if (res < 0) {
		n1 = 0;
		p1 = s1;
		p2++;
	} else if (res > 0) {
		p1++;
		n2 = 0;
		p2 = s2;
	}

	if (n1 != n2)
		return n1 - n2;
	while (*p1 && *p2) {
		if (*p1 != *p2)
			return *p1 - *p2;
		p1++;
		p2++;
		if (isdigit(*p1) && isdigit(*p2))
			return razor_versioncmp(p1, p2);
	}

	return *p1 - *p2;
}

RAZOR_EXPORT struct razor_package *
razor_set_get_package(struct razor_set *set, const char *package)
{
	struct razor_package_iterator *pi;
	struct razor_package *p;
	const char *name, *version, *arch;

	assert (set != NULL);
	assert (package != NULL);

	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &p, &name, &version, &arch)) {
		if (strcmp(package, name) == 0)
			break;
	}
	razor_package_iterator_destroy(pi);

	return p;
}

RAZOR_EXPORT void
razor_package_get_details(struct razor_set *set,
			  struct razor_package *package,
			  const char **summary, const char **description,
			  const char **url, const char **license)
{
	const char *pool = set->details_string_pool.data;

	assert (set != NULL);
	assert (package != NULL);

	if (summary != NULL)
		*summary = &pool[package->summary];
	if (description != NULL)
		*description = &pool[package->description];
	if (url != NULL)
		*url = &pool[package->url];
	if (license != NULL)
		*license = &pool[package->license];
}

RAZOR_EXPORT const char *
razor_property_relation_to_string(struct razor_property *p)
{
	assert (p != NULL);

	switch (p->flags & RAZOR_PROPERTY_RELATION_MASK) {
	case RAZOR_PROPERTY_LESS:
		return "<";

	case RAZOR_PROPERTY_LESS | RAZOR_PROPERTY_EQUAL:
		return "<=";

	case RAZOR_PROPERTY_EQUAL:
		return "=";

	case RAZOR_PROPERTY_GREATER | RAZOR_PROPERTY_EQUAL:
		return ">=";

	case RAZOR_PROPERTY_GREATER:
		return ">";

	default:
		return "?";
	}
}

RAZOR_EXPORT const char *
razor_property_type_to_string(struct razor_property *p)
{
	assert (p != NULL);

	switch (p->flags & RAZOR_PROPERTY_TYPE_MASK) {
	case RAZOR_PROPERTY_REQUIRES:
		return "requires";
	case RAZOR_PROPERTY_PROVIDES:
		return "provides";
	case RAZOR_PROPERTY_CONFLICTS:
		return "conflicts";
	case RAZOR_PROPERTY_OBSOLETES:
		return "obsoletes";
	default:
		return NULL;
	}
}

RAZOR_EXPORT struct razor_entry *
razor_set_find_entry(struct razor_set *set,
		     struct razor_entry *dir, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->file_string_pool.data;
	int len;

	assert (set != NULL);
	assert (dir != NULL);
	assert (pattern != NULL);

	e = (struct razor_entry *) set->files.data + dir->start;
	do {
		n = pool + e->name;
		if (strcmp(pattern + 1, n) == 0)
			return e;
		len = strlen(n);
		if (e->start != 0 && strncmp(pattern + 1, n, len) == 0 &&
		    pattern[len + 1] == '/') {
			return razor_set_find_entry(set, e, pattern + len + 1);
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));

	return NULL;
}

static void
list_dir(struct razor_set *set, struct razor_entry *dir,
	 char *prefix, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->file_string_pool.data;

	e = (struct razor_entry *) set->files.data + dir->start;
	do {
		n = pool + e->name;
		if (pattern && pattern[0] && fnmatch(pattern, n, 0) != 0)
			continue;
		printf("%s/%s\n", prefix, n);
		if (e->start) {
			char *sub = prefix + strlen (prefix);
			*sub = '/';
			strcpy (sub + 1, n);
			list_dir(set, e, prefix, pattern);
			*sub = '\0';
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));
}

RAZOR_EXPORT void
razor_set_list_files(struct razor_set *set, const char *pattern)
{
	struct razor_entry *e;
	char buffer[512], *p, *base;

	assert (set != NULL);

	if (pattern == NULL || !strcmp (pattern, "/")) {
		buffer[0] = '\0';
		list_dir(set, set->files.data, buffer, NULL);
		return;
	}

	strcpy(buffer, pattern);
	e = razor_set_find_entry(set, set->files.data, buffer);
	if (e && e->start > 0) {
		base = NULL;
	} else {
		p = strrchr(buffer, '/');
		if (p) {
			*p = '\0';
			base = p + 1;
		} else {
			base = NULL;
		}
	}
	e = razor_set_find_entry(set, set->files.data, buffer);
	if (e && e->start != 0)
		list_dir(set, e, buffer, base);
}

static struct list *
list_package_files(struct razor_set *set, struct list *r,
		   struct razor_entry *dir, uint32_t end,
		   char *prefix)
{
	struct razor_entry *e, *f, *entries;
	uint32_t next, file;
	char *pool;
	int len;

	entries = (struct razor_entry *) set->files.data;
	pool = set->file_string_pool.data;

	e = entries + dir->start;
	do {
		if (entries + r->data == e) {
			printf("%s/%s\n", prefix, pool + e->name);
			r = list_next(r);
			if (!r)
				return NULL;
			if (r->data >= end)
				return r;
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));

	e = entries + dir->start;
	do {
		if (e->start == 0)
			continue;

		if (e->flags & RAZOR_ENTRY_LAST)
			next = end;
		else {
			f = e + 1;
			while (f->start == 0 && !(f->flags & RAZOR_ENTRY_LAST))
				f++;
			if (f->start == 0)
				next = end;
			else
				next = f->start;
		}

		file = r->data;
		if (e->start <= file && file < next) {
			len = strlen(prefix);
			prefix[len] = '/';
			strcpy(prefix + len + 1, pool + e->name);
			r = list_package_files(set, r, e, next, prefix);
			prefix[len] = '\0';
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST) && r != NULL);

	return r;
}

RAZOR_EXPORT void
razor_set_list_package_files(struct razor_set *set, const char *name)
{
	struct razor_package *package;
	struct list *r;
	uint32_t end;
	char buffer[512];

	assert (set != NULL);
	assert (name != NULL);

	package = razor_set_get_package(set, name);
	/* TODO: we should return the error to the caller */
	if (!package)
		return;

	r = list_first(&package->files, &set->file_pool);
	end = set->files.size / sizeof (struct razor_entry);
	buffer[0] = '\0';
	list_package_files(set, r, set->files.data, end, buffer);
}

/* The diff order matters.  We should sort the packages so that a
 * REMOVE of a package comes before the INSTALL, and so that all
 * requires for a package have been installed before the package.
 **/

RAZOR_EXPORT void
razor_set_diff(struct razor_set *set, struct razor_set *upstream,
	       razor_diff_callback_t callback, void *data)
{
 	struct razor_package_iterator *pi1, *pi2;
 	struct razor_package *p1, *p2;
	const char *name1, *name2, *version1, *version2, *arch1, *arch2;
	int res;

	assert (set != NULL);
	assert (upstream != NULL);

	pi1 = razor_package_iterator_create(set);
	pi2 = razor_package_iterator_create(upstream);

	razor_package_iterator_next(pi1, &p1, &name1, &version1, &arch1);
	razor_package_iterator_next(pi2, &p2, &name2, &version2, &arch2);

	while (p1 || p2) {
		if (p1 && p2) {
			res = strcmp(name1, name2);
			if (res == 0)
				res = razor_versioncmp(version1, version2);
		} else {
			res = 0;
		}

		if (p2 == NULL || res < 0)
			callback(RAZOR_DIFF_ACTION_REMOVE,
				 p1, name1, version1, arch1, data);
		else if (p1 == NULL || res > 0)
			callback(RAZOR_DIFF_ACTION_ADD,
				 p2, name2, version2, arch2, data);

		if (p1 != NULL && res <= 0)
			razor_package_iterator_next(pi1, &p1,
						    &name1, &version1, &arch1);
		if (p2 != NULL && res >= 0)
			razor_package_iterator_next(pi2, &p2,
						    &name2, &version2, &arch2);
	}

	razor_package_iterator_destroy(pi1);
	razor_package_iterator_destroy(pi2);
}

static void
add_new_package(enum razor_diff_action action,
		struct razor_package *package,
		const char *name,
		const char *version,
		const char *arch,
		void *data)
{
	if (action == RAZOR_DIFF_ACTION_ADD)
		razor_package_query_add_package(data, package);
}

RAZOR_EXPORT struct razor_package_iterator *
razor_set_create_remove_iterator(struct razor_set *set,
				 struct razor_set *next)
{
	struct razor_package_query *query;
	struct razor_package_iterator *pi;

	assert (set != NULL);
	assert (next != NULL);

	query = razor_package_query_create(set);
	razor_set_diff(next, set, add_new_package, query);

	pi = razor_package_query_finish(query);

	/* FIXME: We need to figure out the right install order here,
	 * so the post and pre scripts can run. */

	/* sort */

	return pi;
}

RAZOR_EXPORT struct razor_package_iterator *
razor_set_create_install_iterator(struct razor_set *set,
				  struct razor_set *next)
{
	struct razor_package_query *query;
	struct razor_package_iterator *pi;

	assert (set != NULL);
	assert (next != NULL);

	query = razor_package_query_create(next);
	razor_set_diff(set, next, add_new_package, query);

	pi = razor_package_query_finish(query);

	/* FIXME: We need to figure out the right install order here,
	 * so the post and pre scripts can run. */

	/* sort */

	return pi;
}
