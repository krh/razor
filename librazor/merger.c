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

#include <string.h>
#include "razor-internal.h"
#include "razor.h"

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

struct razor_merger *
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

void
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
	     const char *name, uint32_t flags, const char *version)
{
	struct razor_property *p;

	p = array_add(&merger->set->properties, sizeof *p);
	p->name = hashtable_tokenize(&merger->table, name);
	p->flags = flags;
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
			cmp = p1->flags - p2->flags;
		if (cmp == 0)
			cmp = razor_versioncmp(&pool1[p1->version],
					       &pool2[p2->version]);
		if (cmp < 0) {
			map1[i++] = add_property(merger,
						 &pool1[p1->name],
						 p1->flags,
						 &pool1[p1->version]);
		} else if (cmp > 0) {
			map2[j++] = add_property(merger,
						 &pool2[p2->name],
						 p2->flags,
						 &pool2[p2->version]);
		} else  {
			map1[i++] = map2[j++] =
				add_property(merger,
					     &pool1[p1->name],
					     p1->flags,
					     &pool1[p1->version]);
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

struct razor_set *
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
