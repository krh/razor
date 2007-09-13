#define _GNU_SOURCE

#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <expat.h>
#include "sha1.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct array {
	void *data;
	int size, alloc;
};

static void
array_init(struct array *array)
{
	memset(array, 0, sizeof *array);
}

static void
array_release(struct array *array)
{
	free(array->data);
}

static void *
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

static int
write_to_fd(int fd, void *p, size_t size)
{
	int rest, len;

	rest = size;
	while (rest > 0) {
		len = write(fd, p, rest);
		if (len < 0)
			return -1;
		rest -= len;
	}

	return 0;
}

static int
write_to_file(const char *filename, void *p, size_t size)
{
	int fd, err;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;
	err = write_to_fd(fd, p, size);
	close(fd);

	return err;
}

static void *
zalloc(size_t size)
{
	void *p;

	p = malloc(size);
	memset(p, 0, size);

	return p;
}

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

struct razor_set_section razor_sections[] = {
	{ RAZOR_PACKAGES,	offsetof(struct razor_set, packages) },
	{ RAZOR_REQUIRES,	offsetof(struct razor_set, requires) },
	{ RAZOR_PROVIDES,	offsetof(struct razor_set, provides) },
	{ RAZOR_STRING_POOL,	offsetof(struct razor_set, string_pool) },
	{ RAZOR_PROPERTY_POOL,	offsetof(struct razor_set, property_pool) },
};

struct razor_set *
razor_set_create(void)
{
	return zalloc(sizeof(struct razor_set));
}

struct razor_set *
razor_set_open(const char *filename)
{
	struct razor_set *set;
	struct razor_set_section *s;
	struct stat stat;
	struct array *array;
	int fd;

	set = zalloc(sizeof *set);
	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return NULL;
	set->header = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (set->header == MAP_FAILED) {
		free(set);
		return NULL;
	}

	for (s = set->header->sections; ~s->type; s++) {
		if (s->type >= ARRAY_SIZE(razor_sections))
			continue;
		if (s->type != razor_sections[s->type].type)
			continue;
		array = (void *) set + razor_sections[s->type].offset;
		array->data = (void *) set->header + s->offset;
		array->size = s->size;
		array->alloc = s->size;
	}
	close(fd);

	return set;
}

void
razor_set_destroy(struct razor_set *set)
{
	unsigned int size;
	struct array *a;
	int i;

	if (set->header) {
		for (i = 0; set->header->sections[i].type; i++)
			;
		size = set->header->sections[i].type;
		munmap(set->header, size);
		free(set->buckets.data);
	} else {
		for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
			a = (void *) set + razor_sections[i].offset;
			free(a->data);
		}
		free(set->buckets.data);
	}

	free(set);
}

static int
razor_set_write(struct razor_set *set, const char *filename)
{
	char data[4096];
	struct razor_set_header *header = (struct razor_set_header *) data;
	struct array *a;
	unsigned long offset;
	int i, fd;

	memset(data, 0, sizeof data);
	header->magic = RAZOR_MAGIC;
	header->version = RAZOR_VERSION;
	offset = sizeof data;

	for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
		if (razor_sections[i].type != i)
			continue;
		a = (void *) set + razor_sections[i].offset;
		header->sections[i].type = i;
		header->sections[i].offset = offset;
		header->sections[i].size = a->size;
		offset += (a->size + 4095) & ~4095;
	}

	header->sections[i].type = ~0;
	header->sections[i].offset = 0;
	header->sections[i].size = 0;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	write_to_fd(fd, data, sizeof data);
	for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
		if (razor_sections[i].type != i)
			continue;
		a = (void *) set + razor_sections[i].offset;
		write_to_fd(fd, a->data, (a->size + 4095) & ~4095);
	}

	close(fd);

	return 0;
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

unsigned long
razor_set_lookup(struct razor_set *set, const char *key)
{
	unsigned int mask, start, i;
	unsigned long *b;
	char *pool;

	pool = set->string_pool.data;
	mask = set->buckets.alloc - 1;
	start = hash_string(key) * sizeof(unsigned long);

	for (i = 0; i < set->buckets.alloc; i += sizeof *b) {
		b = set->buckets.data + ((start + i) & mask);

		if (*b == 0)
			return 0;

		if (strcmp(key, &pool[*b]) == 0)
			return *b;
	}

	return 0;
}

static unsigned long
add_to_string_pool(struct razor_set *set, const char *key)
{
	int len;
	char *p;

	len = strlen(key) + 1;
	p = array_add(&set->string_pool, len);
	memcpy(p, key, len);

	return p - (char *) set->string_pool.data;
}

static unsigned long
add_to_property_pool(struct razor_set *set, struct array *properties)
{
	unsigned long  *p;

	p = array_add(properties, sizeof *p);
	*p = ~0ul;
	p = array_add(&set->property_pool, properties->size);
	memcpy(p, properties->data, properties->size);

	return p - (unsigned long *) set->property_pool.data;
}

static void
do_insert(struct razor_set *set, unsigned long value)
{
	unsigned int mask, start, i;
	unsigned long *b;
	const char *key;

	key = (char *) set->string_pool.data + value;
	mask = set->buckets.alloc - 1;
	start = hash_string(key) * sizeof(unsigned long);

	for (i = 0; i < set->buckets.alloc; i += sizeof *b) {
		b = set->buckets.data + ((start + i) & mask);
		if (*b == 0) {
			*b = value;
			break;
		}
	}
}

unsigned long
razor_set_insert(struct razor_set *set, const char *key)
{
	unsigned long value, *buckets, *b, *end;
	int alloc;

	alloc = set->buckets.alloc;
	array_add(&set->buckets, 4 * sizeof *buckets);
	if (alloc != set->buckets.alloc) {
		end = set->buckets.data + alloc;
		memset(end, 0, set->buckets.alloc - alloc);
		for (b = set->buckets.data; b < end; b++) {
			value = *b;
			if (value != 0) {
				*b = 0;
				do_insert(set, value);
			}
		}
	}

	value = add_to_string_pool(set, key);
	do_insert (set, value);

	return value;
}

unsigned long
razor_set_tokenize(struct razor_set *set, const char *string)
{
	unsigned long token;

	if (string == NULL)
		return razor_set_tokenize(set, "");

	token = razor_set_lookup(set, string);
	if (token != 0)
		return token;

	return razor_set_insert(set, string);
}

struct import_property_context {
	struct array all;
	struct array package;
};

struct import_context {
	struct razor_set *set;
	struct import_property_context requires;
	struct import_property_context provides;
	struct array packages;
	struct import_package *package;
	unsigned long *requires_map;
	unsigned long *provides_map;
};

struct import_package {
	unsigned long name;
	unsigned long version;
	unsigned long requires;
	unsigned long provides;
	unsigned long index;
};

struct import_property {
	unsigned long name;
	unsigned long version;
	unsigned long package;
	unsigned long index;
	unsigned long unique_index;
};

static void
import_context_add_package(struct import_context *ctx,
			   const char *name, const char *version)
{
	struct import_package *p;

	p = array_add(&ctx->packages, sizeof *p);
	p->name = razor_set_tokenize(ctx->set, name);
	p->version = razor_set_tokenize(ctx->set, version);
	p->index = p - (struct import_package *) ctx->packages.data;

	ctx->package = p;
	array_init(&ctx->requires.package);
	array_init(&ctx->provides.package);
}

void
import_context_finish_package(struct import_context *ctx)
{
	struct import_package *p;

	p = ctx->package;
	p->requires = add_to_property_pool(ctx->set, &ctx->requires.package);
	p->provides = add_to_property_pool(ctx->set, &ctx->provides.package);

	array_release(&ctx->requires.package);
	array_release(&ctx->provides.package);
}

static void
import_context_add_property(struct import_context *ctx,
			    struct import_property_context *pctx,
			    const char *name, const char *version)
{
	struct import_property *p;
	unsigned long *r;

	p = array_add(&pctx->all, sizeof *p);
	p->name = razor_set_tokenize(ctx->set, name);
	p->version = razor_set_tokenize(ctx->set, version);
	p->package = ctx->package->index;
	p->index = p - (struct import_property *) pctx->all.data;

	r = array_add(&pctx->package, sizeof *r);
	*r = p->index;
}

static void
parse_package(struct import_context *ctx, const char **atts, void *data)
{
	const char *name = NULL, *version = NULL;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = atts[i + 1];
		else if (strcmp(atts[i], "version") == 0)
			version = atts[i + 1];
	}

	if (name == NULL || version == NULL) {
		fprintf(stderr, "invalid package tag, "
			"missing name or version attributes\n");
		return;
	}

	import_context_add_package(ctx, name, version);
}

static void
parse_property(struct import_context *ctx, const char **atts, void *data)
{
	const char *name = NULL, *version = NULL;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = atts[i + 1];
		if (strcmp(atts[i], "version") == 0)
			version = atts[i + 1];
	}
	
	if (name == NULL) {
		fprintf(stderr, "invalid tag, missing name attribute\n");
		return;
	}

	import_context_add_property(ctx, data, name, version);
}

static void
start_element(void *data, const char *name, const char **atts)
{
	struct import_context *ctx = data;

	if (strcmp(name, "package") == 0)
		parse_package(ctx, atts, NULL);
	else if (strcmp(name, "requires") == 0)
		parse_property(ctx, atts, &ctx->requires);
	else if (strcmp(name, "provides") == 0)
		parse_property(ctx, atts, &ctx->provides);
}

static void
end_element (void *data, const char *name)
{
	struct import_context *ctx = data;

	if (strcmp(name, "package") == 0)
		import_context_finish_package(ctx);
}

static char *
sha1_to_hex(const unsigned char *sha1)
{
	static int bufno;
	static char hexbuffer[4][50];
	static const char hex[] = "0123456789abcdef";
	char *buffer = hexbuffer[3 & ++bufno], *buf = buffer;
	int i;

	for (i = 0; i < 20; i++) {
		unsigned int val = *sha1++;
		*buf++ = hex[val >> 4];
		*buf++ = hex[val & 0xf];
	}
	*buf = '\0';

	return buffer;
}

static void
razor_prepare_import(struct import_context *ctx)
{
	memset(ctx, 0, sizeof *ctx);
	ctx->set = razor_set_create();
}

static int
razor_import(struct import_context *ctx, const char *filename)
{
	SHA_CTX sha1;
	XML_Parser parser;
	int fd;
	void *p;
	struct stat stat;
	char buf[128];
	unsigned char hash[20];

	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return -1;
	p = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		return -1;

	parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, ctx);
	XML_SetElementHandler(parser, start_element, end_element);
	if (XML_Parse(parser, p, stat.st_size, 1) == XML_STATUS_ERROR) {
		fprintf(stderr,
			"%s at line %d, %s\n",
			XML_ErrorString(XML_GetErrorCode(parser)),
			XML_GetCurrentLineNumber(parser),
			filename);
		return 1;
	}

	XML_ParserFree(parser);

	SHA1_Init(&sha1);
	SHA1_Update(&sha1, p, stat.st_size);
	SHA1_Final(hash, &sha1);

	close(fd);

	snprintf(buf, sizeof buf, "set/%s", sha1_to_hex(hash));
	if (write_to_file(buf, p, stat.st_size) < 0)
		return -1;
	munmap(p, stat.st_size);

	return 0;
}

typedef int (*compare_with_data_func_t)(const void *p1,
					const void *p,
					void *data);

static void
qsort_swap(void *p1, void *p2, size_t size)
{
	char buffer[size];

	memcpy(buffer, p1, size);
	memcpy(p1, p2, size);
	memcpy(p2, buffer, size);
}

void
qsort_with_data(void *base, size_t nelem, size_t size,
		compare_with_data_func_t compare, void *data)
{
	void *p, *start, *end, *pivot;
	int left, right, result;

	p = base;
	start = base;
	end = base + nelem * size;
	pivot = base + (random() % nelem) * size;
	
	while (p < end) {
		result = compare(p, pivot, data);
		if (result < 0) {
			qsort_swap(p, start, size);
			if (start == pivot)
				pivot = p;
			start += size;
			p += size;
		} else if (result == 0) {
			p += size;
		} else {
 			end -= size;
			qsort_swap(p, end, size);
			if (end == pivot)
				pivot = p;
		}
	}

	left = (start - base) / size;
	right = (base + nelem * size - end) / size;
	if (left > 1)
		qsort_with_data(base, left, size, compare, data);
	if (right > 1)
		qsort_with_data(end, right, size, compare, data);
}

static int
compare_packages(const void *p1, const void *p2, void *data)
{
	const struct import_package *pkg1 = p1, *pkg2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	if (pkg1->name == pkg2->name)
		return 0;
	else
		return strcmp(&pool[pkg1->name], &pool[pkg2->name]);
}

static int
compare_properties(const void *p1, const void *p2, void *data)
{
	const struct import_property *prop1 = p1, *prop2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	if (prop1->name == prop2->name)
		return strcmp(&pool[prop1->version], &pool[prop2->version]);
	else
		return strcmp(&pool[prop1->name], &pool[prop2->name]);
}

static unsigned long *
uniqueify_properties(struct razor_set *set,
		     struct array *in, struct array *out)
{
	struct import_property *ip, *end;
	struct razor_property *rp, *rp_end;
	struct array *pkgs, *p;
	unsigned long *map, *r;
	int i, count, unique;

	count = in->size / sizeof(struct import_property);
	qsort_with_data(in->data,
			count,
			sizeof(struct import_property),
			compare_properties,
			set);

	rp = NULL;
	end = in->data + in->size;
	for (ip = in->data; ip < end; ip++) {
		if (rp == NULL ||
		    ip->name != rp->name || ip->version != rp->version) {
			rp = array_add(out, sizeof *rp);
			rp->name = ip->name;
			rp->version = ip->version;
		}
		ip->unique_index = rp - (struct razor_property *) out->data;
	}

	map = malloc(count * sizeof (unsigned long));
	ip = in->data;
	for (i = 0; i < count; i++)
		map[ip[i].index] = ip[i].unique_index;

	unique = out->size / sizeof(*rp);
	pkgs = zalloc(unique * sizeof *pkgs);
	for (ip = in->data; ip < end; ip++) {
		r = array_add(&pkgs[ip->unique_index], sizeof *r);
		*r = ip->package;
	}

	rp_end = out->data + out->size;
	for (rp = out->data, p = pkgs; rp < rp_end; rp++, p++)
		rp->packages = add_to_property_pool(set, p);

	free(pkgs);

	return map;
}

static void
remap_package_links(struct import_context *ctx)
{
	struct import_package *p, *end;
	unsigned long *pool, *r;

	pool = ctx->set->property_pool.data;
	end = ctx->packages.data + ctx->packages.size;
	for (p = ctx->packages.data; p < end; p++) {
		for (r = &pool[p->requires]; ~*r; r++)
			*r = ctx->requires_map[*r];
		for (r = &pool[p->provides]; ~*r; r++)
			*r = ctx->provides_map[*r];
	}
}

static void
remap_property_links(struct import_context *ctx)
{
	struct razor_property *p, *end;
	struct import_package *ip;
	unsigned long *map, *pool, *r;
	int i, count;

	pool = ctx->set->property_pool.data;
	count = ctx->packages.size / sizeof(struct import_package);
	map = malloc(count * sizeof *map);
	ip = ctx->packages.data;
	for (i = 0; i < count; i++)
		map[ip[i].index] = i;

	/* FIXME: This will break if we implement package list sharing
	 * for all properties, since we'll remap those lists more than
	 * once. We should just have a separate pool for property
	 * lists and a separate pool for package lists and remap it as
	 * a flat pool.  Right now, as property lists and package
	 * lists are mixed, we can't do that. */

	end = ctx->set->requires.data + ctx->set->requires.size;
	for (p = ctx->set->requires.data; p < end; p++)
		for (r = &pool[p->packages]; ~*r; r++)
			*r = map[*r];

	end = ctx->set->provides.data + ctx->set->provides.size;
	for (p = ctx->set->provides.data; p < end; p++)
		for (r = &pool[p->packages]; ~*r; r++)
			*r = map[*r];

	free(map);
}

static struct razor_set *
razor_finish_import(struct import_context *ctx)
{
	struct import_package *ip;
	struct razor_package *rp;
	int i, count;

	ctx->requires_map =
		uniqueify_properties(ctx->set, 
				     &ctx->requires.all,
				     &ctx->set->requires);
	ctx->provides_map =
		uniqueify_properties(ctx->set,
				     &ctx->provides.all,
				     &ctx->set->provides);

	remap_package_links(ctx);

	count = ctx->packages.size / sizeof(struct import_package);
	qsort_with_data(ctx->packages.data,
			count,
			sizeof(struct import_package),
			compare_packages,
			ctx->set);

	ip = ctx->packages.data;
	for (i = 0; i < count; i++, ip++, rp++) {
		rp = array_add(&ctx->set->packages, sizeof *rp);
		rp->name = ip->name;
		rp->version = ip->version;
		rp->requires = ip->requires;
		rp->provides = ip->provides;
	}

	remap_property_links(ctx);

	free(ctx->requires.all.data);
	free(ctx->provides.all.data);
	free(ctx->requires_map);
	free(ctx->provides_map);
		
	fprintf(stderr, "parsed %d requires, %d unique\n",
		ctx->requires.all.size / sizeof(struct import_property),
		ctx->set->requires.size / sizeof(struct razor_property));
	fprintf(stderr, "parsed %d provides, %d unique\n",
		ctx->provides.all.size / sizeof(struct import_property),
		ctx->set->provides.size / sizeof(struct razor_property));

	return ctx->set; 
}

/* Import a yum filelist as a razor package set. */

enum {
	YUM_STATE_BEGIN,
	YUM_STATE_PACKAGE_NAME
};

struct yum_context {
	struct import_context ctx;
	struct import_property_context *current_property_context;
	char *name;
	int state;
};

static void
yum_start_element(void *data, const char *name, const char **atts)
{
	struct yum_context *ctx = data;
	const char *n, *version;
	int i;

	if (strcmp(name, "name") == 0) {
		ctx->state = YUM_STATE_PACKAGE_NAME;
	} else if (strcmp(name, "version") == 0) {
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], "ver") == 0)
				version = atts[i + 1];
		}
		import_context_add_package(&ctx->ctx, ctx->name, version);
	} else if (strcmp(name, "rpm:requires") == 0) {
		ctx->current_property_context = &ctx->ctx.requires;
	} else if (strcmp(name, "rpm:provides") == 0) {
		ctx->current_property_context = &ctx->ctx.provides;
	} else if (strcmp(name, "rpm:entry") == 0 &&
		   ctx->current_property_context != NULL) {
		n = NULL;
		version = NULL;
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], "name") == 0)
				n = atts[i + 1];
			else if (strcmp(atts[i], "ver") == 0)
				version = atts[i + 1];
		}

		if (n == NULL) {
			fprintf(stderr, "invalid rpm:entry, "
				"missing name or version attributes\n");
			return;
		}

		import_context_add_property(&ctx->ctx,
					    ctx->current_property_context,
					    n, version);
	}
}

static void
yum_end_element (void *data, const char *name)
{
	struct yum_context *ctx = data;

	if (strcmp(name, "package") == 0) {
		free(ctx->name);
		import_context_finish_package(&ctx->ctx);
	} else if (strcmp(name, "name") == 0) {
		ctx->state = 0;
	} else if (strcmp(name, "rpm:requires") == 0) {
		ctx->current_property_context = NULL;
	} else if (strcmp(name, "rpm:provides") == 0) {
		ctx->current_property_context = NULL;
	}
}

static void
yum_character_data (void *data, const XML_Char *s, int len)
{
	struct yum_context *ctx = data;

	if (ctx->state == YUM_STATE_PACKAGE_NAME)
		ctx->name = strndup(s, len);
}

static struct razor_set *
razor_set_create_from_yum_filelist(int fd)
{
	struct yum_context ctx;
	XML_Parser parser;
	char buf[4096];
	int len;

	razor_prepare_import(&ctx.ctx);

	parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, &ctx);
	XML_SetElementHandler(parser, yum_start_element, yum_end_element);
	XML_SetCharacterDataHandler(parser, yum_character_data);

	while (1) {
		len = read(fd, buf, sizeof buf);
		if (len < 0) {
			fprintf(stderr,
				"couldn't read input: %s\n", strerror(errno));
			return NULL;
		} else if (len == 0)
			break;

		if (XML_Parse(parser, buf, len, 0) == XML_STATUS_ERROR) {
			fprintf(stderr,
				"%s at line %d\n",
				XML_ErrorString(XML_GetErrorCode(parser)),
				XML_GetCurrentLineNumber(parser));
			return NULL;
		}
	}

	XML_ParserFree(parser);

	return razor_finish_import(&ctx.ctx);
}

void
razor_set_list(struct razor_set *set)
{
	struct razor_package *p, *end;
	char *pool;

	pool = set->string_pool.data;
	end = set->packages.data + set->packages.size;
	for (p = set->packages.data; p < end; p++)
		printf("%s %s\n", &pool[p->name], &pool[p->version]);
}

struct razor_set *bsearch_set;

static int
compare_package_name(const void *key, const void *data)
{
	const struct razor_package *p = data;
	char *pool;

	pool = bsearch_set->string_pool.data;

	return strcmp(key, &pool[p->name]);
}

struct razor_package *
razor_set_get_package(struct razor_set *set, const char *package)
{
	bsearch_set = set;
	return bsearch(package, set->packages.data,
		       set->packages.size / sizeof(struct razor_package),
		       sizeof(struct razor_package), compare_package_name);
}

static int
compare_property_name(const void *key, const void *data)
{
	const struct razor_property *p = data;
	char *pool;

	pool = bsearch_set->string_pool.data;

	return strcmp(key, &pool[p->name]);
}

struct razor_property *
razor_set_get_property(struct razor_set *set,
		       struct array *properties,
		       const char *property)
{
	struct razor_property *p, *start;

	bsearch_set = set;
	p = bsearch(property, properties->data,
		    properties->size / sizeof(struct razor_property),
		    sizeof(struct razor_property), compare_property_name);

	start = properties->data;
	while (p > start && (p - 1)->name == p->name)
		p--;

	return p;
}

static void
razor_set_list_all_properties(struct razor_set *set, struct array *properties)
{
	struct razor_property *p, *end;
	char *pool;

	pool = set->string_pool.data;
	end = properties->data + properties->size;
	for (p = properties->data; p < end; p++)
		printf("%s %s\n", &pool[p->name], &pool[p->version]);
}

void
razor_set_list_requires(struct razor_set *set, const char *name)
{
	struct razor_property *p, *requires;
	struct razor_package *package;
	unsigned long *r;
	char *pool;

	if (name) {
		package = razor_set_get_package(set, name);
		r = (unsigned long *) set->property_pool.data +
			package->requires;
		requires = set->requires.data;
		pool = set->string_pool.data;
		while (~*r) {
			p = &requires[*r++];
			printf("%s %s\n", &pool[p->name], &pool[p->version]);
		}
	} else
		razor_set_list_all_properties(set, &set->requires);
}

void
razor_set_list_provides(struct razor_set *set, const char *name)
{
	struct razor_property *p, *provides;
	struct razor_package *package;
	unsigned long *r;
	char *pool;

	if (name) {
		package = razor_set_get_package(set, name);
		r = (unsigned long *) set->property_pool.data +
			package->provides;
		provides = set->provides.data;
		pool = set->string_pool.data;
		while (~*r) {
			p = &provides[*r++];
			printf("%s %s\n", &pool[p->name], &pool[p->version]);
		}
	} else 
		razor_set_list_all_properties(set, &set->provides);
}

void
razor_set_list_property_packages(struct razor_set *set,
				 struct array *properties,
				 const char *name,
				 const char *version)
{
	struct razor_property *property, *end;
	struct razor_package *p, *packages;
	unsigned long *r;
	char *pool;

	if (name == NULL)
		return;

	property = razor_set_get_property(set, properties, name);
	packages = set->packages.data;
	pool = set->string_pool.data;
	end = properties->data + properties->size;
	while (property < end && strcmp(name, &pool[property->name]) == 0) {
		if (version && strcmp(version, &pool[property->version]) != 0)
			goto next;
		r = (unsigned long *)
			set->property_pool.data + property->packages;
		while (~*r) {
			p = &packages[*r++];
			printf("%s %s\n",
			       &pool[p->name], &pool[p->version]);
		}
	next:
		property++;
	}
}

void
razor_set_validate(struct razor_set *set, struct array *unsatisfied)
{
	struct razor_property *r, *p, *rend, *pend;
	unsigned long *u;
	char *pool;

	r = set->requires.data;
	p = set->provides.data;
	rend = set->requires.data + set->requires.size;
	pend = set->provides.data + set->provides.size;
	pool = set->string_pool.data;
	
	while (r < rend) {
		while (p < pend && strcmp(&pool[r->name], &pool[p->name]) > 0)
			p++;
		if (p == pend || strcmp(&pool[r->name], &pool[p->name]) != 0) {
			u = array_add(unsatisfied, sizeof *u);
			*u = r - (struct razor_property *) set->requires.data;
		}
		r++;
	}
}

void
razor_set_list_unsatisfied(struct razor_set *set)
{
	struct array unsatisfied;
	struct razor_property *requires, *r;
	unsigned long *u, *end;
	char *pool;

	array_init(&unsatisfied);
	razor_set_validate(set, &unsatisfied);

	end = unsatisfied.data + unsatisfied.size;
	requires = set->requires.data;
	pool = set->string_pool.data;

	for (u = unsatisfied.data; u < end; u++) {
		r = requires + *u;
		printf("%s %s not satisfied\n",
		       &pool[r->name], &pool[r->version]);
	}

	array_release(&unsatisfied);
}

void
razor_set_info(struct razor_set *set)
{
	unsigned int offset, size;
	int i;

	for (i = 0; i < set->header->sections[i].type; i++) {
		offset = set->header->sections[i].offset;
		size = set->header->sections[i].size;

		switch (set->header->sections[i].type) {
		case RAZOR_PACKAGES:
			printf("package section:\t%dkb\n", size / 1024);
			break;
		case RAZOR_REQUIRES:
			printf("requires section:\t%dkb\n", size / 1024);
			break;
		case RAZOR_PROVIDES:
			printf("provides section:\t%dkb\n", size / 1024);
			break;
		case RAZOR_STRING_POOL:
			printf("string pool:\t\t%dkb\n", size / 1024);
			break;
		case RAZOR_PROPERTY_POOL:
			printf("properties section:\t%dkb\n", size / 1024);
			break;
		}
	}
}

static int
usage(void)
{
	printf("usage: razor [ import FILES | lookup <key> | "
	       "list | list-requires | list-provides | eat-yum | info ]\n");
	exit(1);
}

static const char *repo_filename = "system.repo";
static const char rawhide_repo_filename[] = "rawhide.repo";

int
main(int argc, char *argv[])
{
	int i;
	struct razor_set *set;
	struct stat statbuf;
	struct import_context ctx;
	char *repo;

	repo = getenv("RAZOR_REPO");
	if (repo != NULL)
		repo_filename = repo;

	if (argc < 2) {
		usage();
	} else if (strcmp(argv[1], "import") == 0) {
		if (stat("set", &statbuf) && mkdir("set", 0777)) {
			fprintf(stderr, "could not create directory 'set'\n");
			exit(-1);
		}
			
		razor_prepare_import(&ctx);

		for (i = 2; i < argc; i++) {
			if (razor_import(&ctx, argv[i]) < 0) {
				fprintf(stderr, "failed to import %s\n",
					argv[i]);
				exit(-1);
			}
		}

		set = razor_finish_import(&ctx);

		printf("bucket allocation: %d\n", set->buckets.alloc);
		printf("pool size: %d\n", set->string_pool.size);
		printf("pool allocation: %d\n", set->string_pool.alloc);
		printf("packages: %d\n",
		       set->packages.size / sizeof(struct razor_package));
		printf("requires: %d\n",
		       set->requires.size / sizeof(struct razor_property));
		printf("provides: %d\n",
		       set->provides.size / sizeof(struct razor_property));

		razor_set_write(set, repo_filename);

		razor_set_destroy(set);
	} else if (strcmp(argv[1], "lookup") == 0) {
		set = razor_set_open(repo_filename);
		printf("%s is %lu\n", argv[2],
		       razor_set_lookup(set, argv[2]));
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "list") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_list(set);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "list-requires") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_list_requires(set, argv[2]);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "list-provides") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_list_provides(set, argv[2]);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "what-requires") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_list_property_packages(set, &set->requires,
						 argv[2], argv[3]);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "what-provides") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_list_property_packages(set, &set->provides,
						 argv[2], argv[3]);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "info") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_info(set);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "eat-yum") == 0) {
		set = razor_set_create_from_yum_filelist(STDIN_FILENO);
		if (set == NULL)
			return 1;
		razor_set_write(set, rawhide_repo_filename);
		razor_set_destroy(set);
		printf("wrote %s\n", rawhide_repo_filename);
	} else if (strcmp(argv[1], "validate") == 0) {
		set = razor_set_open(repo_filename);
		if (set == NULL)
			return 1;
		razor_set_list_unsatisfied(set);
		razor_set_destroy(set);
	} else {
		usage();
	}

	return 0;
}
