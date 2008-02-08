#include <stdlib.h>
#include <string.h>

#include "types.h"

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

#define RAZOR_ENTRY_LAST	0x80000000ul
#define RAZOR_IMMEDIATE		0x80000000ul
#define RAZOR_ENTRY_MASK	0x00fffffful

void
list_init(uint32_t *list)
{
	*list = ~0;
}

void
list_set(uint32_t *list, struct array *pool, struct array *items)
{
	uint32_t *p;

	if (items->size == 0) {
		list_init(list);
	} else if (items->size == sizeof (uint32_t)) {
		*list = *(uint32_t *) items->data | RAZOR_IMMEDIATE;
	} else {
		p = array_add(pool, items->size);
		memcpy(p, items->data, items->size);
		p[items->size / sizeof *p - 1] |= RAZOR_ENTRY_LAST;
		*list = p - (uint32_t *) pool->data;
	}
}

uint32_t *
list_first(uint32_t *list, struct array *pool)
{
	if (*list == ~0)
		return NULL;
	else if (*list & RAZOR_IMMEDIATE)
		return list;
	else
		return (uint32_t *) pool->data + (*list & RAZOR_ENTRY_MASK);
}

uint32_t *
list_next(uint32_t *list)
{
	if (*list & ~RAZOR_ENTRY_MASK)
		return NULL;
	return ++list;
}

void
list_remap_pool(struct array *pool, uint32_t *map)
{
	uint32_t *p, *end;

	end = pool->data + pool->size;
	for (p = pool->data; p < end; p++)
		*p = map[LIST_VALUE(p)] | LIST_FLAGS(p);
}

void
list_remap_if_immediate(uint32_t *list, uint32_t *map)
{
	if ((*list & ~RAZOR_ENTRY_MASK) == RAZOR_IMMEDIATE)
		*list = map[LIST_VALUE(list)] | LIST_FLAGS(list);
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
