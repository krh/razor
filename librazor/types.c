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

#include "razor-internal.h"

void
array_init(struct array *array)
{
	memset(array, 0, sizeof *array);
}

void
array_release(struct array *array)
{
	free(array->data);
}

void *
array_add(struct array *array, int size)
{
	int alloc;
	void *data, *p;

	if (array->alloc > 0)
		alloc = array->alloc;
	else
		alloc = 16;

	while (alloc < array->size + size)
		alloc *= 2;

	if (array->alloc < alloc) {
		data = realloc(array->data, alloc);
		if (data == NULL)
			return 0;
		array->data = data;
		array->alloc = alloc;
	}

	p = array->data + array->size;
	array->size += size;

	return p;
}

/* RAZOR_IMMEDIATE and RAZOR_ENTRY_LAST must have the same value */
#define RAZOR_ENTRY_LAST 0x80
#define RAZOR_IMMEDIATE  0x80
#define RAZOR_EMPTY_LIST 0xff

void
list_set_empty(struct list_head *head)
{
	head->list_ptr = ~0;
	head->flags = RAZOR_EMPTY_LIST;
}

void
list_set_ptr(struct list_head *head, uint32_t ptr)
{
	head->list_ptr = ptr;
	head->flags = 0;
}

void
list_set_array(struct list_head *head, struct array *pool,
	       struct array *items, int force_indirect)
{
	struct list *p;

	if (!force_indirect) {
		if (items->size == 0) {
			list_set_empty(head);
			return;
		} else if (items->size == sizeof (uint32_t)) {
			head->list_ptr = *(uint32_t *) items->data;
			head->flags = RAZOR_IMMEDIATE;
			return;
		}
	}

	p = array_add(pool, items->size);
	memcpy(p, items->data, items->size);
	p[items->size / sizeof *p - 1].flags = RAZOR_ENTRY_LAST;
	list_set_ptr(head, p - (struct list *) pool->data);
}

struct list *
list_first(struct list_head *head, struct array *pool)
{
	if (head->flags == RAZOR_EMPTY_LIST)
		return NULL;
	else if (head->flags == RAZOR_IMMEDIATE)
		return (struct list *) head;
	else
		return (struct list *) pool->data + head->list_ptr;
}

struct list *
list_next(struct list *list)
{
	if (list->flags)
		return NULL;
	return ++list;
}

void
list_remap_pool(struct array *pool, uint32_t *map)
{
	struct list *p, *end;

	end = pool->data + pool->size;
	for (p = pool->data; p < end; p++)
		p->data = map[p->data];
}

void
list_remap_head(struct list_head *head, uint32_t *map)
{
	if (head->flags == RAZOR_IMMEDIATE)
		head->list_ptr = map[head->list_ptr];
}


void
hashtable_init(struct hashtable *table, struct array *pool)
{
	array_init(&table->buckets);
	table->pool = pool;
}

void
hashtable_release(struct hashtable *table)
{
	array_release(&table->buckets);
}

static unsigned int
hash_string(const char *key)
{
	const char *p;
	unsigned int hash = 0;

	for (p = key; *p; p++)
		hash = (hash * 617) ^ *p;

	return hash;
}

uint32_t
hashtable_lookup(struct hashtable *table, const char *key)
{
	unsigned int mask, start, i;
	uint32_t *b;
	char *pool;

	pool = table->pool->data;
	mask = table->buckets.alloc - 1;
	start = hash_string(key) * sizeof(uint32_t);

	for (i = 0; i < table->buckets.alloc; i += sizeof *b) {
		b = table->buckets.data + ((start + i) & mask);

		if (*b == 0)
			return 0;

		if (strcmp(key, &pool[*b]) == 0)
			return *b;
	}

	return 0;
}

static void
do_insert(struct hashtable *table, uint32_t value)
{
	unsigned int mask, start, i;
	uint32_t *b;
	const char *key;

	key = (char *) table->pool->data + value;
	mask = table->buckets.alloc - 1;
	start = hash_string(key) * sizeof(uint32_t);

	for (i = 0; i < table->buckets.alloc; i += sizeof *b) {
		b = table->buckets.data + ((start + i) & mask);
		if (*b == 0) {
			*b = value;
			break;
		}
	}
}

static uint32_t
add_to_string_pool(struct hashtable *table, const char *key)
{
	int len;
	char *p;

	len = strlen(key) + 1;
	p = array_add(table->pool, len);
	memcpy(p, key, len);

	return p - (char *) table->pool->data;
}

uint32_t
hashtable_insert(struct hashtable *table, const char *key)
{
	uint32_t value, *buckets, *b, *end;
	int alloc;

	alloc = table->buckets.alloc;
	array_add(&table->buckets, 4 * sizeof *buckets);
	if (alloc != table->buckets.alloc) {
		end = table->buckets.data + alloc;
		memset(end, 0, table->buckets.alloc - alloc);
		for (b = table->buckets.data; b < end; b++) {
			value = *b;
			if (value != 0) {
				*b = 0;
				do_insert(table, value);
			}
		}
	}

	value = add_to_string_pool(table, key);
	do_insert (table, value);

	return value;
}

uint32_t
hashtable_tokenize(struct hashtable *table, const char *string)
{
	uint32_t token;

	if (string == NULL)
		string = "";

	token = hashtable_lookup(table, string);
	if (token != 0)
		return token;

	return hashtable_insert(table, string);
}
