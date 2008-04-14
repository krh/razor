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

#include "razor.h"
#include "razor-internal.h"
#include "types.h"

struct razor_set_section {
	uint32_t type;
	uint32_t offset;
	uint32_t size;
};

struct razor_set_header {
	uint32_t magic;
	uint32_t version;
	struct razor_set_section sections[0];
};

#define RAZOR_MAGIC 0x7a7a7a7a
#define RAZOR_VERSION 1

#define RAZOR_STRING_POOL	0
#define RAZOR_PACKAGES		1
#define RAZOR_PROPERTIES	2
#define RAZOR_FILES		3
#define RAZOR_PACKAGE_POOL	4
#define RAZOR_PROPERTY_POOL	5
#define RAZOR_FILE_POOL		6

struct razor_package {
	uint name  : 24;
	uint flags : 8;
	uint32_t version;
	uint32_t arch;
	struct list_head properties;
	struct list_head files;
};

struct razor_property {
	uint name  : 24;
	uint flags : 6;
	enum razor_property_type type : 2;
	enum razor_version_relation relation : 32;
	uint32_t version;
	struct list_head packages;
};

struct razor_entry {
	uint name  : 24;
	uint flags : 8;
	uint32_t start;
	struct list_head packages;
};

#define RAZOR_ENTRY_LAST	0x80

struct razor_set {
	struct array string_pool;
 	struct array packages;
 	struct array properties;
 	struct array files;
	struct array package_pool;
 	struct array property_pool;
 	struct array file_pool;
	struct razor_set_header *header;
};

struct import_entry {
	uint32_t package;
	char *name;
};

struct import_directory {
	uint32_t name, count;
	struct array files;
	struct array packages;
	struct import_directory *last;
};

struct razor_importer {
	struct razor_set *set;
	struct hashtable table;
	struct razor_package *package;
	struct array properties;
	struct array files;
	struct array file_requires;
};

static void *
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
	{ RAZOR_FILES,		offsetof(struct razor_set, files) },
	{ RAZOR_PACKAGE_POOL,	offsetof(struct razor_set, package_pool) },
	{ RAZOR_PROPERTY_POOL,	offsetof(struct razor_set, property_pool) },
	{ RAZOR_FILE_POOL,	offsetof(struct razor_set, file_pool) },
};

struct razor_set *
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

struct razor_set *
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

void
razor_set_destroy(struct razor_set *set)
{
	unsigned int size;
	struct array *a;
	int i;

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

	free(set);
}

int
razor_set_write_to_fd(struct razor_set *set, int fd)
{
	char data[4096];
	struct razor_set_header *header = (struct razor_set_header *) data;
	struct array *a;
	uint32_t offset;
	int i;

	memset(data, 0, sizeof data);
	header->magic = RAZOR_MAGIC;
	header->version = RAZOR_VERSION;
	offset = sizeof data;

	for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
		if (razor_sections[i].type != i)
			continue;
		a = (void *) set + razor_sections[i].offset;
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
	for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
		if (razor_sections[i].type != i)
			continue;
		a = (void *) set + razor_sections[i].offset;
		razor_write(fd, a->data, a->size);
		razor_write(fd, data, ALIGN(a->size, 4096) - a->size);
	}

	return 0;
}

int
razor_set_write(struct razor_set *set, const char *filename)
{
	int fd, status;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	status = razor_set_write_to_fd(set, fd);
	if (status) {
	    close(fd);
	    return status;
	}

	return close(fd);
}

void
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

void
razor_importer_begin_package(struct razor_importer *importer,
			     const char *name,
			     const char *version,
			     const char *arch)
{
	struct razor_package *p;

	p = array_add(&importer->set->packages, sizeof *p);
	p->name = hashtable_tokenize(&importer->table, name);
	p->flags = 0;
	p->version = hashtable_tokenize(&importer->table, version);
	p->arch = hashtable_tokenize(&importer->table, arch);

	importer->package = p;
	array_init(&importer->properties);
}

void
razor_importer_finish_package(struct razor_importer *importer)
{
	list_set_array(&importer->package->properties,
		       &importer->set->property_pool,
		       &importer->properties,
		       1);

	array_release(&importer->properties);
}

void
razor_importer_add_property(struct razor_importer *importer,
			    const char *name,
			    enum razor_version_relation relation,
			    const char *version,
			    enum razor_property_type type)
{
	struct razor_property *p;
	uint32_t *r;

	p = array_add(&importer->set->properties, sizeof *p);
	p->name = hashtable_tokenize(&importer->table, name);
	p->flags = 0;
	p->type = type;
	p->relation = relation;
	p->version = hashtable_tokenize(&importer->table, version);
	list_set_ptr(&p->packages, importer->package -
		     (struct razor_package *) importer->set->packages.data);

	r = array_add(&importer->properties, sizeof *r);
	*r = p - (struct razor_property *) importer->set->properties.data;

	if (type == RAZOR_PROPERTY_REQUIRES && *name == '/') {
		r = array_add(&importer->file_requires, sizeof *r);
		*r = p->name;
	}
}

void
razor_importer_add_file(struct razor_importer *importer, const char *name)
{
	struct import_entry *e;

	e = array_add(&importer->files, sizeof *e);

	e->package = importer->package -
		(struct razor_package *) importer->set->packages.data;
	e->name = strdup(name);
}

struct razor_importer *
razor_importer_new(void)
{
	struct razor_importer *importer;

	importer = zalloc(sizeof *importer);
	importer->set = razor_set_create();
	hashtable_init(&importer->table, &importer->set->string_pool);

	return importer;
}

/* Destroy an importer without creating the set. */
void
razor_importer_destroy(struct razor_importer *importer)
{
	/* FIXME: write this */
}

static int
versioncmp(const char *s1, const char *s2)
{
	const char *p1, *p2;
	long n1, n2;
	int res;

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
			return versioncmp(p1, p2);
	}

	return *p1 - *p2;
}

static int
compare_packages(const void *p1, const void *p2, void *data)
{
	const struct razor_package *pkg1 = p1, *pkg2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	/* FIXME: what if the flags are different? */
	if (pkg1->name == pkg2->name)
		return versioncmp(&pool[pkg1->version], &pool[pkg2->version]);
	else
		return strcmp(&pool[pkg1->name], &pool[pkg2->name]);
}

static int
compare_properties(const void *p1, const void *p2, void *data)
{
	const struct razor_property *prop1 = p1, *prop2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	if (prop1->name != prop2->name) 
		return strcmp(&pool[prop1->name], &pool[prop2->name]);
	else if (prop1->type != prop2->type)
		return prop1->type - prop2->type;
	else if (prop1->relation != prop2->relation)
		return prop1->relation - prop2->relation;
	else
		return versioncmp(&pool[prop1->version], &pool[prop2->version]);
}

static uint32_t *
uniqueify_properties(struct razor_set *set)
{
	struct razor_property *rp, *up, *rp_end;
	struct array *pkgs, *p;
	struct list_head *r;
	uint32_t *map, *rmap;
	int i, count, unique;

	count = set->properties.size / sizeof(struct razor_property);
	map = razor_qsort_with_data(set->properties.data,
				    count,
				    sizeof(struct razor_property),
				    compare_properties,
				    set);

	rp_end = set->properties.data + set->properties.size;
	rmap = malloc(count * sizeof *map);
	pkgs = zalloc(count * sizeof *pkgs);
	for (rp = set->properties.data, up = rp, i = 0; rp < rp_end; rp++, i++) {
		if (rp->name != up->name || rp->type != up->type ||
		    rp->relation != up->relation || rp->version != up->version) {
			up++;
			up->name = rp->name;
			up->flags = 0;
			up->type = rp->type;
			up->relation = rp->relation;
			up->version = rp->version;
		}

		unique = up - (struct razor_property *) set->properties.data;
		rmap[map[i]] = unique;
		r = array_add(&pkgs[unique], sizeof *r);
		*r = rp->packages;
	}
	free(map);

	if (up != rp)
		up++;
	set->properties.size = (void *) up - set->properties.data;
	rp_end = up;
	for (rp = set->properties.data, p = pkgs; rp < rp_end; rp++, p++) {
		list_set_array(&rp->packages, &set->package_pool, p, 0);
		array_release(p);
	}

	free(pkgs);

	return rmap;
}

static int
compare_filenames(const void *p1, const void *p2, void *data)
{
	const struct import_entry *e1 = p1;
	const struct import_entry *e2 = p2;
	const char *n1 = e1->name;
	const char *n2 = e2->name;

	/* Need to make sure that the contents of a directory
	 * are sorted immediately after it. So "foo/bar" has to
	 * sort before "foo.conf"
	 *
	 * FIXME: this is about 60% slower than strcmp
	 */
	while (*n1 && *n2) {
		if (*n1 < *n2)
			return *n2 == '/' ? 1 : -1;
		else if (*n1 > *n2)
			return *n1 == '/' ? -1 : 1;
		n1++;
		n2++;
	}
	if (*n1)
		return 1;
	else if (*n2)
		return -1;
	else
		return 0;
}

static void
count_entries(struct import_directory *d)
{
	struct import_directory *p, *end;

	p = d->files.data;
	end = d->files.data + d->files.size;
	d->count = 0;
	while (p < end) {
		count_entries(p);
		d->count += p->count + 1;
		p++;
	}		
}

static void
serialize_files(struct razor_set *set,
		struct import_directory *d, struct array *array)
{
	struct import_directory *p, *end;
	struct razor_entry *e = NULL;
	uint32_t s;

	p = d->files.data;
	end = d->files.data + d->files.size;
	s = array->size / sizeof *e + d->files.size / sizeof *p;
	while (p < end) {
		e = array_add(array, sizeof *e);
		e->name = p->name;
		e->flags = 0;
		e->start = p->count > 0 ? s : 0;
		s += p->count;

		list_set_array(&e->packages, &set->package_pool, &p->packages, 0);
		array_release(&p->packages);
		p++;
	}		
	if (e != NULL)
		e->flags |= RAZOR_ENTRY_LAST;

	p = d->files.data;
	end = d->files.data + d->files.size;
	while (p < end) {
		serialize_files(set, p, array);
		p++;
	}
}

static void
remap_property_package_links(struct array *properties, uint32_t *rmap)
{
	struct razor_property *p, *end;

	end = properties->data + properties->size;
	for (p = properties->data; p < end; p++)
		list_remap_head(&p->packages, rmap);
}

static void
build_file_tree(struct razor_importer *importer)
{
	int count, i, length;
	struct import_entry *filenames;
	char *f, *end;
	uint32_t name, *r;
	char dirname[256];
	struct import_directory *d, root;
	struct razor_entry *e;

	count = importer->files.size / sizeof (struct import_entry);
	razor_qsort_with_data(importer->files.data,
			      count,
			      sizeof (struct import_entry),
			      compare_filenames,
			      NULL);

	root.name = hashtable_tokenize(&importer->table, "");
	array_init(&root.files);
	array_init(&root.packages);
	root.last = NULL;

	filenames = importer->files.data;
	for (i = 0; i < count; i++) {
		f = filenames[i].name;
		if (*f != '/')
			continue;
		f++;

		d = &root;
		while (*f) {
			end = strchr(f, '/');
			if (end == NULL)
				end = f + strlen(f);
			length = end - f;
			memcpy(dirname, f, length);
			dirname[length] ='\0';
			name = hashtable_tokenize(&importer->table, dirname);
			if (d->last == NULL || d->last->name != name) {
				d->last = array_add(&d->files, sizeof *d);
				d->last->name = name;
				d->last->last = NULL;
				array_init(&d->last->files);
				array_init(&d->last->packages);
			}
			d = d->last;				
			f = end + 1;
			if (*end == '\0')
				break;
		}

		r = array_add(&d->packages, sizeof *r);
		*r = filenames[i].package;
		free(filenames[i].name);
	}

	count_entries(&root);
	e = importer->set->files.data;
	e->name = root.name;
	e->flags = RAZOR_ENTRY_LAST;
	e->start = importer->files.size ? 1 : 0;
	list_set_empty(&e->packages);

	serialize_files(importer->set, &root, &importer->set->files);

	array_release(&importer->files);
}

static struct razor_entry *
find_entry(struct razor_set *set, struct razor_entry *dir, const char *pattern);

static void
list_to_array(struct list *list, struct array *array)
{
	uint32_t *item;

	while (list) {
		 item = array_add(array, sizeof *item);
		 *item = list->data;
		 list = list_next(list);
	}
}

static int
compare_file_requires(const void *p1, const void *p2, void *data)
{
	uint32_t *f1 = (void *)p1, *f2 = (void *)p2;
	const char *pool = data;

	return strcmp(&pool[*f1], &pool[*f2]);
}

static void
find_file_provides(struct razor_importer *importer)
{
	struct razor_property *prop;
	struct razor_entry *top, *entry;
	struct razor_package *packages;
	struct array pkgprops;
	struct list *pkg;
	uint32_t *req, *req_start, *req_end;
	uint32_t *map, *newprop;
	char *pool;

	pool = importer->set->string_pool.data;
	packages = importer->set->packages.data;
	top = importer->set->files.data;

	req = req_start = importer->file_requires.data;
	req_end = importer->file_requires.data + importer->file_requires.size;
	map = razor_qsort_with_data(req, req_end - req, sizeof *req,
				    compare_file_requires, pool);
	free(map);

	for (req = req_start; req < req_end; req++) {
		if (req > req_start && req[0] == req[-1])
			continue;
		entry = find_entry(importer->set, top, &pool[*req]);
		if (!entry)
			continue;

		for (pkg = list_first(&entry->packages, &importer->set->package_pool); pkg; pkg = list_next(pkg)) {
			prop = array_add(&importer->set->properties, sizeof *prop);
			prop->name = *req;
			prop->type = RAZOR_PROPERTY_PROVIDES;
			prop->relation = RAZOR_VERSION_EQUAL;
			prop->version = hashtable_tokenize(&importer->table, "");
			list_set_ptr(&prop->packages, pkg->data);

			/* Update property list of pkg */
			array_init(&pkgprops);
			list_to_array(list_first(&packages[pkg->data].properties, &importer->set->property_pool), &pkgprops);
			newprop = array_add(&pkgprops, sizeof *newprop);
			*newprop = prop - (struct razor_property *)importer->set->properties.data;
			list_set_array(&packages[pkg->data].properties, &importer->set->property_pool, &pkgprops, 1);
			array_release(&pkgprops);
		}
	}

	array_release(&importer->file_requires);
}

static void
build_package_file_lists(struct razor_set *set, uint32_t *rmap)
{
	struct razor_package *p, *packages;
	struct array *pkgs;
	struct razor_entry *e, *end;
	struct list *r;
	uint32_t *q;
	int i, count;

	count = set->packages.size / sizeof *p;
	pkgs = zalloc(count * sizeof *pkgs);

	end = set->files.data + set->files.size;
	for (e = set->files.data; e < end; e++) {
		list_remap_head(&e->packages, rmap);
		r = list_first(&e->packages, &set->package_pool);
		while (r) {
			q = array_add(&pkgs[r->data], sizeof *q);
			*q = e - (struct razor_entry *) set->files.data;
			r = list_next(r);
		}
	}

	packages = set->packages.data;
	for (i = 0; i < count; i++) {
		list_set_array(&packages[i].files, &set->file_pool, &pkgs[i], 0);
		array_release(&pkgs[i]);
	}
	free(pkgs);
}

struct razor_set *
razor_importer_finish(struct razor_importer *importer)
{
	struct razor_set *set;
	uint32_t *map, *rmap;
	int i, count;

	build_file_tree(importer);
	find_file_provides(importer);

	map = uniqueify_properties(importer->set);
	list_remap_pool(&importer->set->property_pool, map);
	free(map);

	count = importer->set->packages.size / sizeof(struct razor_package);
	map = razor_qsort_with_data(importer->set->packages.data,
				    count,
				    sizeof(struct razor_package),
				    compare_packages,
				    importer->set);

	rmap = malloc(count * sizeof *rmap);
	for (i = 0; i < count; i++)
		rmap[map[i]] = i;
	free(map);

	list_remap_pool(&importer->set->package_pool, rmap);
	build_package_file_lists(importer->set, rmap);
	remap_property_package_links(&importer->set->properties, rmap);
	free(rmap);

	set = importer->set;
	hashtable_release(&importer->table);
	free(importer);

	return set;
}

struct razor_package_iterator {
	struct razor_set *set;
	struct razor_package *package, *end;
	struct list *index;
};

static struct razor_package_iterator *
razor_package_iterator_create_with_index(struct razor_set *set,
					 struct list *index)
{
	struct razor_package_iterator *pi;

	pi = zalloc(sizeof *pi);
	pi->set = set;
	pi->index = index;

	return pi;
}

struct razor_package_iterator *
razor_package_iterator_create(struct razor_set *set)
{
	struct razor_package_iterator *pi;

	pi = zalloc(sizeof *pi);
	pi->set = set;
	pi->end = set->packages.data + set->packages.size;
	pi->package = set->packages.data;

	return pi;
}

static void
razor_package_iterator_init_for_property(struct razor_package_iterator *pi,
					 struct razor_set *set,
					 struct razor_property *property)
{
	memset(pi, 0, sizeof *pi);
	pi->set = set;
	pi->index = list_first(&property->packages, &set->package_pool);
}

struct razor_package_iterator *
razor_package_iterator_create_for_property(struct razor_set *set,
					   struct razor_property *property)
{
	struct list *index;

	index = list_first(&property->packages, &set->package_pool);
	return razor_package_iterator_create_with_index(set, index);
}

int
razor_package_iterator_next(struct razor_package_iterator *pi,
			    struct razor_package **package,
			    const char **name,
			    const char **version,
			    const char **arch)
{
	char *pool;
	int valid;
	struct razor_package *p, *packages;

	if (pi->package) {
		p = pi->package++;
		valid = p < pi->end;
	} else if (pi->index) {
		packages = pi->set->packages.data;
		p = &packages[pi->index->data];
		pi->index = list_next(pi->index);
		valid = 1;
	} else
		valid = 0;

	if (valid) {
		pool = pi->set->string_pool.data;
		*package = p;
		*name = &pool[p->name];
		*version = &pool[p->version];
		*arch = &pool[p->arch];
	} else {
		*package = NULL;
	}

	return valid;
}

void
razor_package_iterator_destroy(struct razor_package_iterator *pi)
{
	free(pi);
}

struct razor_package *
razor_set_get_package(struct razor_set *set, const char *package)
{
	struct razor_package_iterator *pi;
	struct razor_package *p;
	const char *name, *version, *arch;

	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &p, &name, &version, &arch)) {
		if (strcmp(package, name) == 0)
			break;
	}
	razor_package_iterator_destroy(pi);

	return p;
}

struct razor_property_iterator {
	struct razor_set *set;
	struct razor_property *property, *end;
	struct list *index;
};

struct razor_property_iterator *
razor_property_iterator_create(struct razor_set *set,
			       struct razor_package *package)
{
	struct razor_property_iterator *pi;

	pi = zalloc(sizeof *pi);
	pi->set = set;

	if (package) {
		pi->index = list_first(&package->properties,
				       &set->property_pool);
	} else {
		pi->property = set->properties.data;
		pi->end = set->properties.data + set->properties.size;
	}

	return pi;
}

int
razor_property_iterator_next(struct razor_property_iterator *pi,
			     struct razor_property **property,
			     const char **name,
			     enum razor_version_relation *relation,
			     const char **version,
			     enum razor_property_type *type)
{
	char *pool;
	int valid;
	struct razor_property *p, *properties;

	if (pi->property) {
		p = pi->property++;
		valid = p < pi->end;
	} else if (pi->index) {
		properties = pi->set->properties.data;
		p = &properties[pi->index->data];
		pi->index = list_next(pi->index);
		valid = 1;
	} else
		valid = 0;

	if (valid) {
		pool = pi->set->string_pool.data;
		*property = p;
		*name = &pool[p->name];
		*relation = p->relation;
		*version = &pool[p->version];
		*type = p->type;
	} else {
		*property = NULL;
	}

	return valid;
}

void
razor_property_iterator_destroy(struct razor_property_iterator *pi)
{
	free(pi);
}

static struct razor_entry *
find_entry(struct razor_set *set, struct razor_entry *dir, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->string_pool.data;
	int len;

	e = (struct razor_entry *) set->files.data + dir->start;
	do {
		n = pool + e->name;
		if (strcmp(pattern + 1, n) == 0)
			return e;
		len = strlen(n);
		if (e->start != 0 && strncmp(pattern + 1, n, len) == 0 &&
		    pattern[len + 1] == '/') {
			return find_entry(set, e, pattern + len + 1);
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));

	return NULL;
}

static void
list_dir(struct razor_set *set, struct razor_entry *dir,
	 char *prefix, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->string_pool.data;

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

void
razor_set_list_files(struct razor_set *set, const char *pattern)
{
	struct razor_entry *e;
	char buffer[512], *p, *base;

	if (pattern == NULL || !strcmp (pattern, "/")) {
		buffer[0] = '\0';
		list_dir(set, set->files.data, buffer, NULL);
		return;
	}

	strcpy(buffer, pattern);
	e = find_entry(set, set->files.data, buffer);
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
	e = find_entry(set, set->files.data, buffer);
	if (e->start != 0)
		list_dir(set, e, buffer, base);
}

struct razor_package_iterator *
razor_package_iterator_create_for_file(struct razor_set *set,
				       const char *filename)
{
	struct razor_entry *entry;
	struct list *index;

	entry = find_entry(set, set->files.data, filename);
	if (entry == NULL)
		return NULL;
	
	index = list_first(&entry->packages, &set->package_pool);
	return razor_package_iterator_create_with_index(set, index);
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
	pool = set->string_pool.data;

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

void
razor_set_list_package_files(struct razor_set *set, const char *name)
{
	struct razor_package *package;
	struct list *r;
	uint32_t end;
	char buffer[512];

	package = razor_set_get_package(set, name);

	r = list_first(&package->files, &set->file_pool);
	end = set->files.size / sizeof (struct razor_entry);
	buffer[0] = '\0';
	list_package_files(set, r, set->files.data, end, buffer);
}

#define UPSTREAM_SOURCE 0x80

struct source {
	struct razor_set *set;
	uint32_t *property_map;
	uint32_t *file_map;
};

struct razor_merger {
	struct razor_set *set;
	struct hashtable table;
	struct source source1;
	struct source source2;
};

static struct razor_merger *
razor_merger_create(struct razor_set *set1, struct razor_set *set2)
{
	struct razor_merger *merger;
	int count;
	size_t size;

	merger = zalloc(sizeof *merger);
	merger->set = razor_set_create();
	hashtable_init(&merger->table, &merger->set->string_pool);

	merger->source1.set = set1;
	count = set1->properties.size / sizeof (struct razor_property);
	size = count * sizeof merger->source1.property_map[0];
	merger->source1.property_map = zalloc(size);
	count = set1->files.size / sizeof (struct razor_entry);
	size = count * sizeof merger->source1.file_map[0];
	merger->source1.file_map = zalloc(size);

	merger->source2.set = set2;
	count = set2->properties.size / sizeof (struct razor_property);
	size = count * sizeof merger->source2.property_map[0];
	merger->source2.property_map = zalloc(size);
	count = set2->files.size / sizeof (struct razor_entry);
	size = count * sizeof merger->source2.file_map[0];
	merger->source2.file_map = zalloc(size);

	return merger;
}

static void
razor_merger_add_package(struct razor_merger *merger,
			 struct razor_package *package)
{
	char *pool;
	struct list *r;
	struct razor_package *p;
	struct razor_set *set1;
	struct source *source;
	uint32_t flags;

	set1 = merger->source1.set;
	if (set1->packages.data <= (void *) package &&
	    (void *) package < set1->packages.data + set1->packages.size) {
		source = &merger->source1;
		flags = 0;
	} else {
		source = &merger->source2;
		flags = UPSTREAM_SOURCE;
	}

	pool = source->set->string_pool.data;
	p = array_add(&merger->set->packages, sizeof *p);
	p->name = hashtable_tokenize(&merger->table, &pool[package->name]);
	p->flags = flags;
	p->version = hashtable_tokenize(&merger->table,
					&pool[package->version]);
	p->arch = hashtable_tokenize(&merger->table,
				     &pool[package->arch]);

	p->properties = package->properties;
	r = list_first(&package->properties, &source->set->property_pool);
	while (r) {
		source->property_map[r->data] = 1;
		r = list_next(r);
	}

	p->files = package->files;
	r = list_first(&package->files, &source->set->file_pool);
	while (r) {
		source->file_map[r->data] = 1;
		r = list_next(r);
	}
}

static uint32_t
add_property(struct razor_merger *merger,
	     const char *name, enum razor_version_relation relation,
	     const char *version, int type)
{
	struct razor_property *p;

	p = array_add(&merger->set->properties, sizeof *p);
	p->name = hashtable_tokenize(&merger->table, name);
	p->flags = 0;
	p->type = type;
	p->relation = relation;
	p->version = hashtable_tokenize(&merger->table, version);

	return p - (struct razor_property *) merger->set->properties.data;
}

static void
merge_properties(struct razor_merger *merger)
{
	struct razor_property *p1, *p2;
	struct razor_set *set1, *set2;
	uint32_t *map1, *map2;
	int i, j, cmp, count1, count2;
	char *pool1, *pool2;

	set1 = merger->source1.set;
	set2 = merger->source2.set;
	map1 = merger->source1.property_map;
	map2 = merger->source2.property_map;

	i = 0;
	j = 0;
	pool1 = set1->string_pool.data;
	pool2 = set2->string_pool.data;

	count1 = set1->properties.size / sizeof *p1;
	count2 = set2->properties.size / sizeof *p2;
	while (i < count1 || j < count2) {
		if (i < count1 && map1[i] == 0) {
			i++;
			continue;
		}
		if (j < count2 && map2[j] == 0) {
			j++;
			continue;
		}
		p1 = (struct razor_property *) set1->properties.data + i;
		p2 = (struct razor_property *) set2->properties.data + j;
		if (i < count1 && j < count2)
			cmp = strcmp(&pool1[p1->name], &pool2[p2->name]);
		else if (i < count1)
			cmp = -1;
		else
			cmp = 1;
		if (cmp == 0)
			cmp = p1->type - p2->type;
		if (cmp == 0)
			cmp = p1->relation - p2->relation;
		if (cmp == 0)
			cmp = versioncmp(&pool1[p1->version],
					 &pool2[p2->version]);
		if (cmp < 0) {
			map1[i++] = add_property(merger,
						 &pool1[p1->name],
						 p1->relation,
						 &pool1[p1->version],
						 p1->type);
		} else if (cmp > 0) {
			map2[j++] = add_property(merger,
						 &pool2[p2->name],
						 p2->relation,
						 &pool2[p2->version],
						 p2->type);
		} else  {
			map1[i++] = map2[j++] = add_property(merger,
							     &pool1[p1->name],
							     p1->relation,
							     &pool1[p1->version],
							     p1->type);
		}
	}
}

static void
emit_properties(struct list_head *properties, struct array *source_pool,
		uint32_t *map, struct array *pool)
{
	uint32_t r;
	struct list *p, *q;

	r = pool->size / sizeof *q;
	p = list_first(properties, source_pool);
	while (p) {
		q = array_add(pool, sizeof *q);
		q->data = map[p->data];
		q->flags = p->flags;
		p = list_next(p);
	}

	list_set_ptr(properties, r);
}

static uint32_t
add_file(struct razor_merger *merger, const char *name)
{
	struct razor_entry *e;

	e = array_add(&merger->set->files, sizeof *e);
	e->name = hashtable_tokenize(&merger->table, name);
	e->flags = 0;
	e->start = 0;

	return e - (struct razor_entry *)merger->set->files.data;
}

/* FIXME. Blah */
static int
fix_file_map(uint32_t *map,
	     struct razor_entry *files,
	     struct razor_entry *top)
{
	uint32_t e;
	int found_file = 0;

	e = top->start;
	do {
		if (files[e].start)
			fix_file_map(map, files, &files[e]);
		if (map[e])
			found_file = 1;
	} while (!(files[e++].flags & RAZOR_ENTRY_LAST));

	if (found_file)
		map[top - files] = 1;
	return found_file;
}

struct merge_directory {
	uint32_t merged, dir1, dir2;
};

static void
merge_one_directory(struct razor_merger *merger, struct merge_directory *md)
{
	struct razor_entry *root1, *root2, *mroot, *e1, *e2;
	struct razor_set *set1, *set2;
	struct array merge_stack;
	struct merge_directory *child_md, *end_md;
	uint32_t *map1, *map2, start, last;
	int cmp;
	char *pool1, *pool2;

	set1 = merger->source1.set;
	set2 = merger->source2.set;
	map1 = merger->source1.file_map;
	map2 = merger->source2.file_map;
	pool1 = set1->string_pool.data;
	pool2 = set2->string_pool.data;
	root1 = (struct razor_entry *) set1->files.data;
	root2 = (struct razor_entry *) set2->files.data;

	array_init(&merge_stack);

	start = merger->set->files.size / sizeof (struct razor_entry);
	last = 0;
	e1 = md->dir1 ? root1 + md->dir1 : NULL;
	e2 = md->dir2 ? root2 + md->dir2 : NULL;
	while (e1 || e2) {
		if (!e2 && !map1[e1 - root1]) {
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
			continue;
		}
		if (!e1 && !map2[e2 - root2]) {
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
			continue;
		}
		if (e1 && !map1[e1 - root1] &&
		    e2 && !map1[e2 - root2]) {
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
			continue;
		}

		if (!e1)
			cmp = 1;
		else if (!e2)
			cmp = -1;
		else {
			cmp = strcmp (&pool1[e1->name],
				      &pool2[e2->name]);
		}

		if (cmp < 0) {
			if (map1[e1 - root1]) {
				map1[e1 - root1] = last =
					add_file(merger, &pool1[e1->name]);
				if (e1->start) {
					child_md = array_add(&merge_stack, sizeof (struct merge_directory));
					child_md->merged = last;
					child_md->dir1 = e1->start;
					child_md->dir2 = 0;
				}
			}
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
		} else if (cmp > 0) {
			if (map2[e2 - root2]) {
				map2[e2 - root2] = last =
					add_file(merger, &pool2[e2->name]);
				if (e2->start) {
					child_md = array_add(&merge_stack, sizeof (struct merge_directory));
					child_md->merged = last;
					child_md->dir1 = 0;
					child_md->dir2 = e2->start;
				}
			}
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
		} else {
			map1[e1 - root1] = map2[e2- root2] = last =
				add_file(merger, &pool1[e1->name]);
			if (e1->start || e2->start) {
				child_md = array_add(&merge_stack, sizeof (struct merge_directory));
				child_md->merged = last;
				child_md->dir1 = e1->start;
				child_md->dir2 = e2->start;
			}
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
		}
	}

	mroot = (struct razor_entry *)merger->set->files.data;
	if (last) {
		mroot[last].flags = RAZOR_ENTRY_LAST;
		mroot[md->merged].start = start;
	} else
		mroot[md->merged].start = 0;

	end_md = merge_stack.data + merge_stack.size;
	for (child_md = merge_stack.data; child_md < end_md; child_md++)
		merge_one_directory(merger, child_md);
	array_release(&merge_stack);
}

static void
merge_files(struct razor_merger *merger)
{
	struct razor_entry *root;
	struct merge_directory md;
	uint32_t *map1, *map2;

	map1 = merger->source1.file_map;
	map2 = merger->source2.file_map;

	md.merged = 0;

	if (merger->source1.set->files.size) {
		root = (struct razor_entry *) merger->source1.set->files.data;
		if (root->start)
			fix_file_map(map1, root, root);
		md.dir1 = root->start;
	} else
		md.dir1 = 0;

	if (merger->source2.set->files.size) {
		root = (struct razor_entry *) merger->source2.set->files.data;
		if (root->start)
			fix_file_map(map2, root, root);
		md.dir2 = root->start;
	} else
		md.dir2 = 0;

	merge_one_directory(merger, &md);
}

static void
emit_files(struct list_head *files, struct array *source_pool,
	   uint32_t *map, struct array *pool)
{
	uint32_t r;
	struct list *p, *q;

	r = pool->size / sizeof *q;
	p = list_first(files, source_pool);
	while (p) {
		q = array_add(pool, sizeof *q);
		q->data = map[p->data];
		q->flags = p->flags;
		p = list_next(p);
	}

	list_set_ptr(files, r);
}

/* Rebuild property->packages maps.  We can't just remap these, as a
 * property may have lost or gained a number of packages.  Allocate an
 * array per property and loop through the packages and add them to
 * the arrays for their properties. */
static void
rebuild_property_package_lists(struct razor_set *set)
{
	struct array *pkgs, *a;
	struct razor_package *pkg, *pkg_end;
	struct razor_property *prop, *prop_end;
	struct list *r;
	uint32_t *q;
	int count;

	count = set->properties.size / sizeof (struct razor_property);
	pkgs = zalloc(count * sizeof *pkgs);
	pkg_end = set->packages.data + set->packages.size;

	for (pkg = set->packages.data; pkg < pkg_end; pkg++) {
		r = list_first(&pkg->properties, &set->property_pool);
		while (r) {
			q = array_add(&pkgs[r->data], sizeof *q);
			*q = pkg - (struct razor_package *) set->packages.data;
			r = list_next(r);
		}
	}

	prop_end = set->properties.data + set->properties.size;
	a = pkgs;
	for (prop = set->properties.data; prop < prop_end; prop++, a++) {
		list_set_array(&prop->packages, &set->package_pool, a, 0);
		array_release(a);
	}
	free(pkgs);
}

static void
rebuild_file_package_lists(struct razor_set *set)
{
	struct array *pkgs, *a;
	struct razor_package *pkg, *pkg_end;
	struct razor_entry *entry, *entry_end;
	struct list *r;
	uint32_t *q;
	int count;

	count = set->files.size / sizeof (struct razor_entry);
	pkgs = zalloc(count * sizeof *pkgs);
	pkg_end = set->packages.data + set->packages.size;

	for (pkg = set->packages.data; pkg < pkg_end; pkg++) {
		r = list_first(&pkg->files, &set->file_pool);
		while (r) {
			q = array_add(&pkgs[r->data], sizeof *q);
			*q = pkg - (struct razor_package *) set->packages.data;
			r = list_next(r);
		}
	}

	entry_end = set->files.data + set->files.size;
	a = pkgs;
	for (entry = set->files.data; entry < entry_end; entry++, a++) {
		list_set_array(&entry->packages, &set->package_pool, a, 0);
		array_release(a);
	}
	free(pkgs);
}

static struct razor_set *
razor_merger_finish(struct razor_merger *merger)
{
	struct razor_set *result;
	struct razor_package *p, *pend;

	/* As we built the package list, we filled out a bitvector of
	 * the properties that are referenced by the packages in the
	 * new set.  Now we do a parallel loop through the properties
	 * and emit those marked in the bit vector to the new set.  In
	 * the process, we update the bit vector to actually map from
	 * indices in the old property list to indices in the new
	 * property list for both sets. */

	merge_properties(merger);
	merge_files(merger);

	/* Now we loop through the packages again and emit the
	 * property lists, remapped to point to the new properties. */

	pend = merger->set->packages.data + merger->set->packages.size;
	for (p = merger->set->packages.data; p < pend; p++) {
		struct source *src;

		if (p->flags & UPSTREAM_SOURCE)
			src = &merger->source2;
		else
			src = &merger->source1;

		emit_properties(&p->properties,
				&src->set->property_pool,
				src->property_map,
				&merger->set->property_pool);
		emit_files(&p->files,
			   &src->set->file_pool,
			   src->file_map,
			   &merger->set->file_pool);
		p->flags &= ~UPSTREAM_SOURCE;
	}

	rebuild_property_package_lists(merger->set);
	rebuild_file_package_lists(merger->set);

	result = merger->set;
	hashtable_release(&merger->table);
	free(merger);

	return result;
}

/* The diff order matters.  We should sort the packages so that a
 * REMOVE of a package comes before the INSTALL, and so that all
 * requires for a package have been installed before the package.
 **/

void
razor_set_diff(struct razor_set *set, struct razor_set *upstream,
	       razor_package_callback_t callback, void *data)
{
 	struct razor_package_iterator *pi1, *pi2;
 	struct razor_package *p1, *p2;
	const char *name1, *name2, *version1, *version2, *arch1, *arch2;
	int res;

	pi1 = razor_package_iterator_create(set);
	pi2 = razor_package_iterator_create(upstream);

	razor_package_iterator_next(pi1, &p1, &name1, &version1, &arch1);
	razor_package_iterator_next(pi2, &p2, &name2, &version2, &arch2);

	while (p1 || p2) {
		if (p1 && p2) {
			res = strcmp(name1, name2);
			if (res == 0)
				res = versioncmp(version1, version2);
		} else {
			res = 0;
		}

		if (p2 == NULL || res < 0)
			callback(name1, version1, NULL, arch1, data);
		else if (p1 == NULL || res > 0)
			callback(name2, NULL, version2, arch2, data);

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

static int
provider_satisfies_requirement(struct razor_property *provider,
			       const char *provider_strings,
			       enum razor_version_relation relation,
			       const char *required)
{
	int cmp, len;
	const char *provided = &provider_strings[provider->version];

	if (!*required)
		return 1;
	if (!*provided) {
		if (relation >= RAZOR_VERSION_EQUAL)
			return 1;
		else
			return 0;
	}

	cmp = versioncmp(provided, required);

	switch (relation) {
	case RAZOR_VERSION_LESS:
		return cmp < 0;

	case RAZOR_VERSION_LESS_OR_EQUAL:
		if (cmp <= 0)
			return 1;
		/* fall through: FIXME, make sure this is correct */

	case RAZOR_VERSION_EQUAL:
		if (cmp == 0)
			return 1;

		/* "foo == 1.1" is satisfied by "foo 1.1-2" */
		len = strlen(required);
		if (!strncmp(required, provided, len) && provided[len] == '-')
			return 1;
		return 0;

	case RAZOR_VERSION_GREATER_OR_EQUAL:
		return cmp >= 0;

	case RAZOR_VERSION_GREATER:
		return cmp > 0;
	}

	/* shouldn't happen */
	return 0;
}

#define TRANS_PACKAGE_PRESENT		1
#define TRANS_PACKAGE_UPDATE		2
#define TRANS_PROPERTY_SATISFIED	0x80000000

struct transaction_set {
	struct razor_set *set;
	uint32_t *packages;
	uint32_t *properties;
};

struct razor_transaction {
	int package_count, errors;
	struct transaction_set system, upstream;
	int changes;
};

static void
transaction_set_init(struct transaction_set *ts, struct razor_set *set)
{
	int count;

	ts->set = set;
	count = set->packages.size / sizeof (struct razor_package);
	ts->packages = zalloc(count * sizeof *ts->packages);
	count = set->properties.size / sizeof (struct razor_property);
	ts->properties = zalloc(count * sizeof *ts->properties);
}

static void
transaction_set_release(struct transaction_set *ts)
{
	free(ts->packages);
	free(ts->properties);
}

static void
transaction_set_install_package(struct transaction_set *ts,
				struct razor_package *package)
{
	struct razor_package *pkgs;
	struct list *prop;
	int i;

	pkgs = ts->set->packages.data;
	i = package - pkgs;
	if (ts->packages[i] == TRANS_PACKAGE_PRESENT)
		return;

	ts->packages[i] = TRANS_PACKAGE_PRESENT;

	prop = list_first(&package->properties, &ts->set->property_pool);
	while (prop) {
		ts->properties[prop->data]++;
		prop = list_next(prop);
	}
}

static void
transaction_set_remove_package(struct transaction_set *ts,
			       struct razor_package *package)
{
	struct razor_package *pkgs;
	struct list *prop;
	int i;

	pkgs = ts->set->packages.data;
	i = package - pkgs;
	if (ts->packages[i] == 0)
		return;

	ts->packages[i] = 0;

	prop = list_first(&package->properties, &ts->set->property_pool);
	while (prop) {
		ts->properties[prop->data]--;
		prop = list_next(prop);
	}
}

struct razor_transaction *
razor_transaction_create(struct razor_set *system, struct razor_set *upstream)
{
	struct razor_transaction *trans;
	struct razor_package *p, *spkgs, *pend;

	trans = zalloc(sizeof *trans);
	transaction_set_init(&trans->system, system);
	transaction_set_init(&trans->upstream, upstream);

	spkgs = trans->system.set->packages.data;
	pend = trans->system.set->packages.data +
		trans->system.set->packages.size;
	for (p = spkgs; p < pend; p++)
		transaction_set_install_package(&trans->system, p);

	return trans;
}

void
razor_transaction_install_package(struct razor_transaction *trans,
				  struct razor_package *package)
{
	transaction_set_install_package(&trans->upstream, package);
	trans->changes++;
}

void
razor_transaction_remove_package(struct razor_transaction *trans,
				 struct razor_package *package)
{
	transaction_set_remove_package(&trans->system, package);
	trans->changes++;
}

void
razor_transaction_update_package(struct razor_transaction *trans,
				  struct razor_package *package)
{
	struct razor_package *spkgs;

	spkgs = trans->system.set->packages.data;
	trans->system.packages[package - spkgs] |= TRANS_PACKAGE_UPDATE;
}

struct prop_iter {
	struct razor_property *p, *start, *end;
	const char *pool;
	uint32_t *present;
};

static void
prop_iter_init(struct prop_iter *pi, struct transaction_set *ts)
{
	pi->p = ts->set->properties.data;
	pi->start = ts->set->properties.data;
	pi->end = ts->set->properties.data + ts->set->properties.size;
	pi->pool = ts->set->string_pool.data;
	pi->present = ts->properties;
}

static int
prop_iter_next(struct prop_iter *pi,
	       enum razor_property_type type, struct razor_property **p)
{
	while (pi->p < pi->end) {
		if (pi->present[pi->p - pi->start] && pi->p->type == type) {
			*p = pi->p++;
			return 1;
		}
		pi->p++;
	}

	return 0;
}

static struct razor_property *
prop_iter_seek_to(struct prop_iter *pi,
		  enum razor_property_type type, const char *match)
{
	uint32_t name;

	while (pi->p < pi->end && strcmp(&pi->pool[pi->p->name], match) < 0)
		pi->p++;

	if (pi->p == pi->end || strcmp(&pi->pool[pi->p->name], match) > 0)
		return NULL;

	name = pi->p->name;
	while (pi->p < pi->end &&
	       pi->p->name == name &&
	       pi->p->type != type)
		pi->p++;

	if (pi->p == pi->end || pi->p->name != name)
		return NULL;

	return pi->p;
}

/* Remove packages from set that provide any of the matching (same
 * name and type) providers from ppi onwards that match the
 * requirement that rpi points to. */
static void
remove_matching_providers(struct razor_transaction *trans,
			  struct prop_iter *ppi,
			  enum razor_version_relation relation,
			  const char *version)
{
	struct razor_property *p;
	struct razor_package *pkg, *pkgs;
	struct razor_package_iterator pkg_iter;
	struct razor_set *set;
	const char *n, *v, *a;

	if (ppi->present == trans->system.properties)
		set = trans->system.set;
	else
		set = trans->upstream.set;
   
	pkgs = (struct razor_package *) set->packages.data;
	for (p = ppi->p; 
	     p < ppi->end && 
	     p->name == ppi->p->name &&
	     p->type == ppi->p->type;
	     p++) {
		if (!provider_satisfies_requirement(p, ppi->pool,
						    relation, version))
			continue;
		    
		razor_package_iterator_init_for_property(&pkg_iter, set, p);
		while (razor_package_iterator_next(&pkg_iter,
						   &pkg, &n, &v, &a)) {
			fprintf(stderr, "removing %s-%s\n", n, v);
			razor_transaction_remove_package(trans, pkg);
		}
	}
}

static void
flag_matching_providers(struct razor_transaction *trans,
			  struct prop_iter *ppi,
			  struct prop_iter *rpi,
			  unsigned int flag)
{
	struct razor_property *p;
	struct razor_package *pkg, *pkgs;
	struct razor_package_iterator pkg_iter;
	struct razor_set *set;
	const char *name, *version, *arch;
	uint32_t *flags;

	if (ppi->present == trans->system.properties) {
		set = trans->system.set;
		flags = trans->system.packages;
	} else {
		set = trans->upstream.set;
		flags = trans->upstream.packages;
	}
   
	pkgs = (struct razor_package *) set->packages.data;
	for (p = ppi->p; 
	     p < ppi->end && 
		     p->name == ppi->p->name &&
		     p->type == ppi->p->type;
	     p++) {
		if (!provider_satisfies_requirement(p, ppi->pool,
						    rpi->p->relation,
						    &rpi->pool[rpi->p->version]))
			continue;
		    
		razor_package_iterator_init_for_property(&pkg_iter, set, p);
		while (razor_package_iterator_next(&pkg_iter, &pkg,
						   &name, &version, &arch))
			flags[pkg - pkgs] |= flag;
	}
}

static struct razor_package *
pick_matching_provider(struct razor_set *set,
		       struct prop_iter *ppi,
		       enum razor_version_relation relation,
		       const char *version)
{
	struct razor_property *p;
	struct razor_package *pkgs;
	struct list *i;

	/* This is where we decide which pkgs to pull in to satisfy a
	 * requirement.  There may be several different providers
	 * (different versions) and each version of a provider may
	 * come from a number of packages.  We pick the first package
	 * from the first provider that matches. */

	pkgs = set->packages.data;
	for (p = ppi->p;
	     p < ppi->end &&
		     p->name == ppi->p->name &&
		     p->type == ppi->p->type &&
		     ppi->present[p - ppi->start] == 0;
	     p++) {
		if (!provider_satisfies_requirement(p, ppi->pool,
						    relation, version))
			continue;

		i = list_first(&p->packages, &set->package_pool);

		return &pkgs[i->data];
	}

	return NULL;
}

static void
remove_obsoleted_packages(struct razor_transaction *trans)
{
	struct razor_property *up;
	struct razor_package *spkgs;
	struct prop_iter spi, upi;

	spkgs = trans->system.set->packages.data;
	prop_iter_init(&spi, &trans->system);
	prop_iter_init(&upi, &trans->upstream);
	
	while (prop_iter_next(&upi, RAZOR_PROPERTY_OBSOLETES, &up)) {
		if (!prop_iter_seek_to(&spi, RAZOR_PROPERTY_PROVIDES,
				       &upi.pool[up->name]))
			continue;
		remove_matching_providers(trans, &spi, up->relation,
					  &upi.pool[up->version]);
	}
}

static int
any_provider_satisfies_requirement(struct prop_iter *ppi,
				   enum razor_version_relation relation,
				   const char *version)
{
	struct razor_property *p;

	for (p = ppi->p;
	     p < ppi->end &&
		     p->name == ppi->p->name &&
		     p->type == ppi->p->type;
	     p++) {
		if (ppi->present[p - ppi->start] > 0 &&
		    provider_satisfies_requirement(p, ppi->pool,
						   relation, version))
			return 1;
	}

	return 0;
}

static void
clear_requires_flags(struct transaction_set *ts)
{
	struct razor_property *p;
	const char *pool;
	int i, count;

	count = ts->set->properties.size / sizeof *p;
	p = ts->set->properties.data;
	pool = ts->set->string_pool.data;
	for (i = 0; i < count; i++) {
		ts->properties[i] &= ~TRANS_PROPERTY_SATISFIED;
		if (strncmp(&pool[p[i].name], "rpmlib(", 7) == 0)
			ts->properties[i] |= TRANS_PROPERTY_SATISFIED;
	}
}

static void
mark_satisfied_requires(struct razor_transaction *trans,
			struct transaction_set *rts,
			struct transaction_set *pts)
{
	struct prop_iter rpi, ppi;
	struct razor_property *rp;

	prop_iter_init(&rpi, rts);
	prop_iter_init(&ppi, pts);

	while (prop_iter_next(&rpi, RAZOR_PROPERTY_REQUIRES, &rp)) {
		if (!prop_iter_seek_to(&ppi, RAZOR_PROPERTY_PROVIDES,
				       &rpi.pool[rp->name]))
			continue;

		if (any_provider_satisfies_requirement(&ppi, rp->relation,
						       &rpi.pool[rp->version]))
			rpi.present[rp - rpi.start] |= TRANS_PROPERTY_SATISFIED;
	}
}

static void
mark_all_satisfied_requires(struct razor_transaction *trans)
{
	clear_requires_flags(&trans->system);
	clear_requires_flags(&trans->upstream);
	mark_satisfied_requires(trans, &trans->system, &trans->system);
	mark_satisfied_requires(trans, &trans->system, &trans->upstream);
	mark_satisfied_requires(trans, &trans->upstream, &trans->system);
	mark_satisfied_requires(trans, &trans->upstream, &trans->upstream);
}

static void
update_unsatisfied_packages(struct razor_transaction *trans)
{
	struct razor_package *spkgs, *pkg;
	struct razor_property *sp;
	struct prop_iter spi;
	struct razor_package_iterator pkg_iter;
	const char *name, *version, *arch;

	spkgs = trans->system.set->packages.data;
	prop_iter_init(&spi, &trans->system);
	
	while (prop_iter_next(&spi, RAZOR_PROPERTY_REQUIRES, &sp)) {
		if (spi.present[sp - spi.start] & TRANS_PROPERTY_SATISFIED)
			continue;
		
		razor_package_iterator_init_for_property(&pkg_iter,
							 trans->system.set,
							 sp);
		while (razor_package_iterator_next(&pkg_iter, &pkg,
						   &name, &version, &arch))
			trans->system.packages[pkg - spkgs] |=
				TRANS_PACKAGE_UPDATE;
	}
}

void
razor_transaction_update_all(struct razor_transaction *trans)
{
	struct razor_package *p;
	int i, count;

	count = trans->system.set->packages.size / sizeof *p;
	for (i = 0; i < count; i++)
		trans->system.packages[i] |= TRANS_PACKAGE_UPDATE;
}

static void
update_conflicted_packages(struct razor_transaction *trans)
{
	struct razor_package *pkg, *spkgs;
	struct razor_property *up, *sp;
	struct prop_iter spi, upi;
	struct razor_package_iterator pkg_iter;
	const char *name, *version, *arch;

	spkgs = trans->system.set->packages.data;
	prop_iter_init(&spi, &trans->system);
	prop_iter_init(&upi, &trans->upstream);

	while (prop_iter_next(&spi, RAZOR_PROPERTY_CONFLICTS, &sp)) {
		if (!prop_iter_seek_to(&upi, RAZOR_PROPERTY_PROVIDES,
				       &spi.pool[sp->name]))
			continue;

		if (!any_provider_satisfies_requirement(&upi, sp->relation,
							&spi.pool[sp->version]))
			continue;

		razor_package_iterator_init_for_property(&pkg_iter,
							 trans->system.set,
							 sp);
		while (razor_package_iterator_next(&pkg_iter, &pkg,
						   &name, &version, &arch))
			trans->system.packages[pkg - spkgs] |=
				TRANS_PACKAGE_UPDATE;
	}

	prop_iter_init(&spi, &trans->system);
	prop_iter_init(&upi, &trans->upstream);

	while (prop_iter_next(&upi, RAZOR_PROPERTY_CONFLICTS, &up)) {
		sp = prop_iter_seek_to(&spi, RAZOR_PROPERTY_PROVIDES,
				       &upi.pool[upi.p->name]);

		flag_matching_providers(trans,
					&spi, &upi, TRANS_PACKAGE_UPDATE);
	}
}

static void
pull_in_requirements(struct razor_transaction *trans,
		     struct prop_iter *rpi, struct prop_iter *ppi)
{
	struct razor_property *rp, *pp;
	struct razor_package *pkg, *upkgs;

	upkgs = trans->upstream.set->packages.data;
	while (prop_iter_next(rpi, RAZOR_PROPERTY_REQUIRES, &rp)) {
		if (rpi->present[rp - rpi->start] & TRANS_PROPERTY_SATISFIED)
			continue;

		pp = prop_iter_seek_to(ppi, RAZOR_PROPERTY_PROVIDES,
				       &rpi->pool[rpi->p->name]);
		if (pp == NULL)
			continue;
		pkg = pick_matching_provider(trans->upstream.set,
					     ppi, rp->relation,
					     &rpi->pool[rp->version]);
		if (pkg == NULL) {
			/* FIXME: Use an error flags instead so we
			 * only report error once. */
			fprintf(stderr, "could not satisfy req %s ? %s\n",
				&rpi->pool[rp->name], &rpi->pool[rp->version]);
			continue;
		}

		trans->upstream.packages[pkg - upkgs] |= TRANS_PACKAGE_UPDATE;
	}
}

static void
pull_in_all_requirements(struct razor_transaction *trans)
{
	struct prop_iter rpi, ppi;

	prop_iter_init(&rpi, &trans->system);
	prop_iter_init(&ppi, &trans->upstream);
	pull_in_requirements(trans, &rpi, &ppi);
	
	prop_iter_init(&rpi, &trans->upstream);
	prop_iter_init(&ppi, &trans->upstream);
	pull_in_requirements(trans, &rpi, &ppi);
}

static void
flush_scheduled_system_updates(struct razor_transaction *trans)
{
 	struct razor_package_iterator *pi;
 	struct razor_package *p, *pkg, *spkgs;
	struct prop_iter ppi;
	const char *name, *version, *arch;

	spkgs = trans->system.set->packages.data;
	pi = razor_package_iterator_create(trans->system.set);
	prop_iter_init(&ppi, &trans->upstream);

	while (razor_package_iterator_next(pi, &p, &name, &version, &arch)) {
		if (!(trans->system.packages[p - spkgs] & TRANS_PACKAGE_UPDATE))
			continue;

		if (!prop_iter_seek_to(&ppi, RAZOR_PROPERTY_PROVIDES, name)) {
			fprintf(stderr, "nothing provides %s\n", name);
			continue;
		}

		pkg = pick_matching_provider(trans->upstream.set, &ppi,
					     RAZOR_VERSION_GREATER, version);
		if (pkg == NULL) {
			fprintf(stderr,
				"no newer version of %s available\n", name);
			continue;
		}
		
		fprintf(stderr, "updating %s from %s to %s\n",
			name, version, &ppi.pool[pkg->version]);

		razor_transaction_remove_package(trans, p);
		razor_transaction_install_package(trans, pkg);
	}

	razor_package_iterator_destroy(pi);
}

static void
flush_scheduled_upstream_updates(struct razor_transaction *trans)
{
 	struct razor_package_iterator *pi;
 	struct razor_package *p, *upkgs;
	struct prop_iter spi;
	const char *name, *version, *arch;

	upkgs = trans->upstream.set->packages.data;
	pi = razor_package_iterator_create(trans->upstream.set);
	prop_iter_init(&spi, &trans->system);

	while (razor_package_iterator_next(pi, &p, &name, &version, &arch)) {
		if (!(trans->upstream.packages[p - upkgs] & TRANS_PACKAGE_UPDATE))
			continue;

		if (!prop_iter_seek_to(&spi, RAZOR_PROPERTY_PROVIDES, name))
			continue;
		remove_matching_providers(trans, &spi,
					  RAZOR_VERSION_LESS, version);
		razor_transaction_install_package(trans, p);
	}
}

int
razor_transaction_resolve(struct razor_transaction *trans)
{
	int last = 0;

	flush_scheduled_system_updates(trans);

	while (last < trans->changes) {
		last = trans->changes;
		remove_obsoleted_packages(trans);
		mark_all_satisfied_requires(trans);
		update_unsatisfied_packages(trans);
		update_conflicted_packages(trans);
		flush_scheduled_system_updates(trans);
		pull_in_all_requirements(trans);
		flush_scheduled_upstream_updates(trans);
	}

	return trans->changes;
}

int
razor_transaction_unsatisfied_property(struct razor_transaction *trans,
				       const char *name,
				       enum razor_version_relation rel,
				       const char *version,
				       enum razor_property_type type)
{
	struct prop_iter pi;
	struct razor_property *p;

	prop_iter_init(&pi, &trans->system);
	while (prop_iter_next(&pi, type, &p)) {
		if (!(trans->system.properties[p - pi.start] & TRANS_PROPERTY_SATISFIED) &&
		    p->relation == rel &&
		    strcmp(&pi.pool[p->name], name) == 0 &&
		    strcmp(&pi.pool[p->version], version) == 0)
		    
			return 1;
	}

	prop_iter_init(&pi, &trans->upstream);
	while (prop_iter_next(&pi, type, &p)) {
		if (!(trans->upstream.properties[p - pi.start] & TRANS_PROPERTY_SATISFIED) &&
		    p->relation == rel &&
		    strcmp(&pi.pool[p->name], name) == 0 &&
		    strcmp(&pi.pool[p->version], version) == 0)
		    
			return 1;
	}

	return 0;
}

struct razor_set *
razor_transaction_finish(struct razor_transaction *trans)
{
	struct razor_merger *merger;
	struct razor_package *u, *uend, *upkgs, *s, *send, *spkgs;
	char *upool, *spool;
	int cmp;

	s = trans->system.set->packages.data;
	spkgs = trans->system.set->packages.data;
	send = trans->system.set->packages.data +
		trans->system.set->packages.size;
	spool = trans->system.set->string_pool.data;

	u = trans->upstream.set->packages.data;
	upkgs = trans->upstream.set->packages.data;
	uend = trans->upstream.set->packages.data +
		trans->upstream.set->packages.size;
	upool = trans->upstream.set->string_pool.data;

	merger = razor_merger_create(trans->system.set, trans->upstream.set);
	while (s < send || u < uend) {
		if (s < send && u < uend)
			cmp = strcmp(&spool[s->name], &upool[u->name]);
		else if (s < send)
			cmp = -1;
		else
			cmp = 1;

		if (cmp < 0) {
			if (trans->system.packages[s - spkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, s);
			s++;
		} else if (cmp == 0) {
			if (trans->system.packages[s - spkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, s);
			if (trans->upstream.packages[u - upkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, u);

			s++;
			u++;
		} else {
			if (trans->upstream.packages[u - upkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, u);
			u++;
		}
	}

	razor_transaction_destroy(trans);

	return razor_merger_finish(merger);
}

void
razor_transaction_destroy(struct razor_transaction *trans)
{
	transaction_set_release(&trans->system);
	transaction_set_release(&trans->upstream);
	free(trans);

	/* FIXME: free upstream if it was created as an empty set */
}
