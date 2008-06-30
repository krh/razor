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

#include <stdarg.h>
#include <string.h>
#include <assert.h>

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

static struct razor_package_iterator *
razor_package_iterator_create_empty(struct razor_set *set)
{
	struct razor_package_iterator *pi;
	return zalloc(sizeof *pi);
}

RAZOR_EXPORT struct razor_package_iterator *
razor_package_iterator_create(struct razor_set *set)
{
	struct razor_package_iterator *pi;

	assert (set != NULL);

	pi = zalloc(sizeof *pi);
	pi->set = set;
	pi->end = set->packages.data + set->packages.size;
	pi->package = set->packages.data;

	return pi;
}

RAZOR_EXPORT void
razor_package_iterator_init_for_property(struct razor_package_iterator *pi,
					 struct razor_set *set,
					 struct razor_property *property)
{
	assert (pi != NULL);
	assert (set != NULL);
	assert (property != NULL);

	memset(pi, 0, sizeof *pi);
	pi->set = set;
	pi->index = list_first(&property->packages, &set->package_pool);
}

RAZOR_EXPORT struct razor_package_iterator *
razor_package_iterator_create_for_property(struct razor_set *set,
					   struct razor_property *property)
{
	struct list *index;

	assert (set != NULL);
	assert (property != NULL);

	index = list_first(&property->packages, &set->package_pool);
	return razor_package_iterator_create_with_index(set, index);
}

RAZOR_EXPORT struct razor_package_iterator *
razor_package_iterator_create_for_file(struct razor_set *set,
				       const char *filename)
{
	struct razor_entry *entry;
	struct list *index;

	assert (set != NULL);
	assert (filename != NULL);

	entry = razor_set_find_entry(set, set->files.data, filename);
	if (entry == NULL)
		return razor_package_iterator_create_empty(set);

	index = list_first(&entry->packages, &set->package_pool);
	return razor_package_iterator_create_with_index(set, index);
}

/**
 * razor_package_iterator_next:
 * @pi: a %razor_package_iterator
 * @package: a %razor_package
 *
 * Gets the next iteratr along with any vararg data.
 * The vararg must be terminated with zero.
 *
 * Example: razor_package_iterator_next (pi, package, RAZOR_DETAIL_NAME, &name, 0);
 **/
RAZOR_EXPORT int
razor_package_iterator_next(struct razor_package_iterator *pi,
			    struct razor_package **package, ...)
{
	va_list args;
	int valid;
	struct razor_package *p, *packages;

	assert (pi != NULL);

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

	if (valid == 0) {
		*package = NULL;
		goto out;
	}

	*package = p;

	va_start(args, NULL);
	razor_package_get_details_varg (pi->set, p, args);
	va_end (args);
out:
	return valid;
}

RAZOR_EXPORT void
razor_package_iterator_destroy(struct razor_package_iterator *pi)
{
	assert (pi != NULL);

	if (pi->free_index)
		free(pi->index);

	free(pi);
}

RAZOR_EXPORT struct razor_property_iterator *
razor_property_iterator_create(struct razor_set *set,
			       struct razor_package *package)
{
	struct razor_property_iterator *pi;

	assert (set != NULL);

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

RAZOR_EXPORT int
razor_property_iterator_next(struct razor_property_iterator *pi,
			     struct razor_property **property,
			     const char **name,
			     uint32_t *flags,
			     const char **version)
{
	char *pool;
	int valid;
	struct razor_property *p, *properties;

	assert (pi != NULL);

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

RAZOR_EXPORT void
razor_property_iterator_destroy(struct razor_property_iterator *pi)
{
	free(pi);
}

struct razor_package_query {
	struct razor_set *set;
	char *vector;
	int count;
};

RAZOR_EXPORT struct razor_package_query *
razor_package_query_create(struct razor_set *set)
{
	struct razor_package_query *pq;
	int count;

	assert (set != NULL);

	pq = zalloc(sizeof *pq);
	pq->set = set;
	count = set->packages.size / sizeof(struct razor_package);
	pq->vector = zalloc(count * sizeof(char));

	return pq;
}

RAZOR_EXPORT void
razor_package_query_add_package(struct razor_package_query *pq,
				struct razor_package *p)
{
	struct razor_package *packages;

	assert (pq != NULL);
	assert (p != NULL);

	packages = pq->set->packages.data;
	pq->count += pq->vector[p - packages] ^ 1;
	pq->vector[p - packages] = 1;
}

RAZOR_EXPORT void
razor_package_query_add_iterator(struct razor_package_query *pq,
				 struct razor_package_iterator *pi)
{
	struct razor_package *packages, *p;

	assert (pq != NULL);
	assert (pi != NULL);

	packages = pq->set->packages.data;
	while (razor_package_iterator_next(pi, &p, 0)) {
		pq->count += pq->vector[p - packages] ^ 1;
		pq->vector[p - packages] = 1;
	}
}

RAZOR_EXPORT struct razor_package_iterator *
razor_package_query_finish(struct razor_package_query *pq)
{
	struct razor_package_iterator *pi;
	struct razor_set *set;
	struct list *index;
	int i, j;

	assert (pq != NULL);

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
