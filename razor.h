#ifndef _RAZOR_H_
#define _RAZOR_H_

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct array {
	void *data;
	int size, alloc;
};

struct razor_set_section {
	unsigned int type;
	unsigned int offset;
	unsigned int size;
};

struct razor_set_header {
	unsigned int magic;
	unsigned int version;
	struct razor_set_section sections[0];
};

#define RAZOR_MAGIC 0x7a7a7a7a
#define RAZOR_VERSION 1

#define RAZOR_PACKAGES 0
#define RAZOR_REQUIRES 1
#define RAZOR_PROVIDES 2
#define RAZOR_STRING_POOL 3
#define RAZOR_PROPERTY_POOL 4

struct razor_package {
	unsigned long name;
	unsigned long version;
	unsigned long requires;
	unsigned long provides;
};

struct razor_property {
	unsigned long name;
	unsigned long version;
	unsigned long packages;
};

struct razor_set {
	struct array buckets;
	struct array string_pool;
	struct array property_pool;
 	struct array packages;
 	struct array requires;
 	struct array provides;
	struct razor_set_header *header;
};

struct import_property_context {
	struct array *all;
	struct array package;
};

struct import_context {
	struct razor_set *set;
	struct import_property_context requires;
	struct import_property_context provides;
	struct razor_package *package;
	unsigned long *requires_map;
	unsigned long *provides_map;
};

void import_context_add_package(struct import_context *ctx,
				const char *name, const char *version);
void import_context_add_property(struct import_context *ctx,
				 struct import_property_context *pctx,
				 const char *name, const char *version);
void import_context_finish_package(struct import_context *ctx);

unsigned long razor_set_tokenize(struct razor_set *set, const char *string);
void razor_prepare_import(struct import_context *ctx);
struct razor_set *razor_finish_import(struct import_context *ctx);

struct razor_set *razor_import_rzr_files(int count, const char **files);
struct razor_set *razor_set_create_from_yum_filelist(int fd);

#endif /* _RAZOR_H_ */
