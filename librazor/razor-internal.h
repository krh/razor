#ifndef _RAZOR_INTERNAL_H_
#define _RAZOR_INTERNAL_H_

#include <stdlib.h>
#include <stdint.h>

/* GCC visibility */
#if defined(__GNUC__) && __GNUC__ >= 4
#define RAZOR_EXPORT __attribute__ ((visibility("default")))
#else
#define RAZOR_EXPORT
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ALIGN(value, base) (((value) + (base - 1)) & ~((base) - 1))

void *zalloc(size_t size);

struct array {
	void *data;
	int size, alloc;
};

void array_init(struct array *array);
void array_release(struct array *array);
void *array_add(struct array *array, int size);


struct list_head {
	uint32_t list_ptr : 24;
	uint32_t flags    : 8;
};

struct list {
	uint32_t data  : 24;
	uint32_t flags : 8;
};

void list_set_empty(struct list_head *head);
void list_set_ptr(struct list_head *head, uint32_t ptr);
void list_set_array(struct list_head *head, struct array *pool, struct array *items, int force_indirect);

struct list *list_first(struct list_head *head, struct array *pool);
struct list *list_next(struct list *list);

void list_remap_pool(struct array *pool, uint32_t *map);
void list_remap_head(struct list_head *list, uint32_t *map);


struct hashtable {
	struct array buckets;
	struct array *pool;
};

void hashtable_init(struct hashtable *table, struct array *pool);
void hashtable_release(struct hashtable *table);
uint32_t hashtable_insert(struct hashtable *table, const char *key);
uint32_t hashtable_lookup(struct hashtable *table, const char *key);
uint32_t hashtable_tokenize(struct hashtable *table, const char *string);


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

#define RAZOR_MAGIC 		0x7a7a7a7a
#define RAZOR_DETAILS_MAGIC 	0x7a7a7a7b
#define RAZOR_FILES_MAGIC 	0x7a7a7a7c
#define RAZOR_VERSION 1

#define RAZOR_STRING_POOL		0
#define RAZOR_PACKAGES			1
#define RAZOR_PROPERTIES		2
#define RAZOR_PACKAGE_POOL		3
#define RAZOR_PROPERTY_POOL		4

#define RAZOR_DETAILS_STRING_POOL	0

#define RAZOR_FILES			0
#define RAZOR_FILE_POOL			1
#define RAZOR_FILE_STRING_POOL		2

struct razor_package {
	uint name  : 24;
	uint flags : 8;
	uint32_t version;
	uint32_t arch;
	uint32_t summary;
	uint32_t description;
	uint32_t url;
	uint32_t license;
	struct list_head properties;
	struct list_head files;
};


struct razor_property {
	uint32_t name;
	uint32_t flags;
	uint32_t version;
	struct list_head packages;
};

struct razor_entry {
	uint32_t name  : 24;
	uint32_t flags : 8;
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
	struct array file_string_pool;
	struct array details_string_pool;
	struct razor_set_header *header;
	struct razor_set_header *details_header;
	struct razor_set_header *files_header;
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
	struct hashtable file_table;
	struct hashtable details_table;
	struct razor_package *package;
	struct array properties;
	struct array files;
	struct array file_requires;
};

struct razor_package_iterator {
	struct razor_set *set;
	struct razor_package *package, *end;
	struct list *index;
	int free_index;
};

void
razor_package_iterator_init_for_property(struct razor_package_iterator *pi,
					 struct razor_set *set,
					 struct razor_property *property);

struct razor_property_iterator {
	struct razor_set *set;
	struct razor_property *property, *end;
	struct list *index;
};

struct razor_entry *
razor_set_find_entry(struct razor_set *set,
		     struct razor_entry *dir, const char *pattern);

struct razor_merger *
razor_merger_create(struct razor_set *set1, struct razor_set *set2);
void
razor_merger_add_package(struct razor_merger *merger,
			 struct razor_package *package);
struct razor_set *
razor_merger_finish(struct razor_merger *merger);

/* Utility functions */

int razor_create_dir(const char *root, const char *path);
int razor_write(int fd, const void *data, size_t size);


typedef int (*razor_compare_with_data_func_t)(const void *p1,
					      const void *p,
					      void *data);
uint32_t *
razor_qsort_with_data(void *base, size_t nelem, size_t size,
		      razor_compare_with_data_func_t compare, void *data);

#endif /* _RAZOR_INTERNAL_H_ */
