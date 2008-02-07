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
