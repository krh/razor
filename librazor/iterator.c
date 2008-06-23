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

void
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

struct razor_package_iterator *
razor_package_iterator_create_for_file(struct razor_set *set,
				       const char *filename)
{
	struct razor_entry *entry;
	struct list *index;

	entry = razor_set_find_entry(set, set->files.data, filename);
	if (entry == NULL)
		return NULL;

	index = list_first(&entry->packages, &set->package_pool);
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
	if (pi->free_index)
		free(pi->index);

	free(pi);
}

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
			     uint32_t *flags,
			     const char **version)
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
		*flags = p->flags;
		*version = &pool[p->version];
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

struct razor_package_query {
	struct razor_set *set;
	char *vector;
	int count;
};

struct razor_package_query *
razor_package_query_create(struct razor_set *set)
{
	struct razor_package_query *pq;
	int count;

	pq = zalloc(sizeof *pq);
	pq->set = set;
	count = set->packages.size / sizeof(struct razor_package);
	pq->vector = zalloc(count * sizeof(char));

	return pq;
}

void
razor_package_query_add_package(struct razor_package_query *pq,
				struct razor_package *p)
{
	struct razor_package *packages;

	packages = pq->set->packages.data;
	pq->count += pq->vector[p - packages] ^ 1;
	pq->vector[p - packages] = 1;
}

void
razor_package_query_add_iterator(struct razor_package_query *pq,
				 struct razor_package_iterator *pi)
{
	struct razor_package *packages, *p;
	const char *name, *version, *arch;

	packages = pq->set->packages.data;
	while (razor_package_iterator_next(pi, &p, &name, &version, &arch)) {
		pq->count += pq->vector[p - packages] ^ 1;
		pq->vector[p - packages] = 1;
	}
}

struct razor_package_iterator *
razor_package_query_finish(struct razor_package_query *pq)
{
	struct razor_package_iterator *pi;
	struct razor_set *set;
	struct list *index;
	int i, j;

	set = pq->set;
	if (pq->count > 0)
		index = zalloc(pq->count * sizeof *index);
	else
		index = NULL;

	for (i = 0, j = 0; j < pq->count; i++) {
		if (!pq->vector[i])
			continue;

		index[j].data = i;
		if (j == pq->count - 1)
			index[j].flags = 0x80;
		j++;
	}

	free(pq->vector);
	free(pq);

	pi = razor_package_iterator_create_with_index(set, index);
	pi->free_index = 1;

	return pi;
}
