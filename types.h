#ifndef _RAZOR_TYPES_H_
#define _RAZOR_TYPES_H_

#include <stdint.h>

struct array {
	void *data;
	int size, alloc;
};

void array_init(struct array *array);
void array_release(struct array *array);
void *array_add(struct array *array, int size);


void list_init(uint32_t *list);
void list_set(uint32_t *list, struct array *pool, struct array *items);
uint32_t *list_first(uint32_t *list, struct array *pool);
uint32_t *list_next(uint32_t *list);
void list_remap_pool(struct array *pool, uint32_t *map);
void list_remap_if_immediate(uint32_t *list, uint32_t *map);
#define LIST_VALUE(list) (*(list) & RAZOR_ENTRY_MASK)
#define LIST_FLAGS(list) (*(list) & ~RAZOR_ENTRY_MASK)

struct hashtable {
	struct array buckets;
	struct array *pool;
};

void hashtable_init(struct hashtable *table, struct array *pool);
void hashtable_release(struct hashtable *table);
uint32_t hashtable_insert(struct hashtable *table, const char *key);
uint32_t hashtable_lookup(struct hashtable *table, const char *key);
uint32_t hashtable_tokenize(struct hashtable *table, const char *string);

#endif /* _RAZOR_TYPES_H_ */
