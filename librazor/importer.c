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

#include <string.h>
#include "razor-internal.h"
#include "razor.h"

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
razor_importer_add_details(struct razor_importer *importer,
			   const char *summary,
			   const char *description,
			   const char *url,
			   const char *license)
{
	importer->package->summary = hashtable_tokenize(&importer->details_table, summary);
	importer->package->description = hashtable_tokenize(&importer->details_table, description);
	importer->package->url = hashtable_tokenize(&importer->details_table, url);
	importer->package->license = hashtable_tokenize(&importer->details_table, license);
}

void
razor_importer_add_property(struct razor_importer *importer,
			    const char *name,
			    uint32_t flags,
			    const char *version)
{
	struct razor_property *p;
	uint32_t *r;

	p = array_add(&importer->set->properties, sizeof *p);
	p->name = hashtable_tokenize(&importer->table, name);
	p->flags = flags;
	p->version = hashtable_tokenize(&importer->table, version);
	list_set_ptr(&p->packages, importer->package -
		     (struct razor_package *) importer->set->packages.data);

	r = array_add(&importer->properties, sizeof *r);
	*r = p - (struct razor_property *) importer->set->properties.data;

	if (((flags & RAZOR_PROPERTY_TYPE_MASK) == RAZOR_PROPERTY_REQUIRES) &&
	    *name == '/') {
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
razor_importer_create(void)
{
	struct razor_importer *importer;

	importer = zalloc(sizeof *importer);
	importer->set = razor_set_create();
	hashtable_init(&importer->table, &importer->set->string_pool);
	hashtable_init(&importer->details_table,
		       &importer->set->details_string_pool);
	hashtable_init(&importer->file_table,
		       &importer->set->file_string_pool);

	return importer;
}

/* Destroy an importer without creating the set. */
void
razor_importer_destroy(struct razor_importer *importer)
{
	/* FIXME: write this */
}

static int
compare_packages(const void *p1, const void *p2, void *data)
{
	const struct razor_package *pkg1 = p1, *pkg2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	/* FIXME: what if the flags are different? */
	if (pkg1->name == pkg2->name)
		return razor_versioncmp(&pool[pkg1->version], &pool[pkg2->version]);
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
	else if (prop1->flags != prop2->flags)
		return prop1->flags - prop2->flags;
	else if (prop1->version != prop2->version)
		return razor_versioncmp(&pool[prop1->version], &pool[prop2->version]);
	else
		return prop1->packages.list_ptr - prop2->packages.list_ptr;
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
		if (rp->name != up->name ||
		    rp->flags != up->flags ||
		    rp->version != up->version) {
			up++;
			up->name = rp->name;
			up->flags = rp->flags;
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

	root.name = hashtable_tokenize(&importer->file_table, "");
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
			name = hashtable_tokenize(&importer->file_table,
						  dirname);
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
		entry = razor_set_find_entry(importer->set, top, &pool[*req]);
		if (!entry)
			continue;

		for (pkg = list_first(&entry->packages, &importer->set->package_pool); pkg; pkg = list_next(pkg)) {
			prop = array_add(&importer->set->properties, sizeof *prop);
			prop->name = *req;
			prop->flags =
				RAZOR_PROPERTY_PROVIDES | RAZOR_PROPERTY_EQUAL;
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
	hashtable_release(&importer->details_table);
	hashtable_release(&importer->file_table);
	free(importer);

	return set;
}
