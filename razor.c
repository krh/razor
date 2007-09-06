#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <expat.h>
#include "sha1.h"

struct array {
	void *data;
	int size, alloc;
};

static void *
array_add(struct array *array, int size)
{
	int alloc;
	void *data, *p;

	if (array->alloc > 0)
		alloc = array->alloc;
	else
		alloc = 1024;

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

struct razor_set_header {
	unsigned int magic;
	unsigned int version;
	struct { unsigned int type, offset; } sections[0];
};

#define RAZOR_MAGIC 0x7a7a7a7a
#define RAZOR_VERSION 1

#define RAZOR_BUCKETS 1
#define RAZOR_STRINGS 2
#define RAZOR_PACKAGES 3
#define RAZOR_REQUIRES 4
#define RAZOR_PROVIDES 5

struct razor_package {
	unsigned long name;
	unsigned long version;
};

struct razor_property {
	unsigned long name;
	unsigned long version;
	unsigned long packages;
};

struct razor_set {
	struct array buckets;
	struct array string_pool;
 	struct array packages;
 	struct array requires;
 	struct array provides;
	struct razor_set_header *header;
};

struct razor_set *
razor_set_create(void)
{
	struct razor_set *set;
	char *p;

	set = zalloc(sizeof(struct razor_set));
	p = array_add(&set->string_pool, 1);
	*p = '\0';

	return set;
}

struct razor_set *
razor_set_open(const char *filename)
{
	struct razor_set *set;
	struct stat stat;
	unsigned int size, offset;
	int fd, i;

	set = zalloc(sizeof *set);
	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return NULL;
	set->header = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (set->header == MAP_FAILED) {
		free(set);
		return NULL;
	}

	for (i = 0; i < set->header->sections[i].type; i++) {
		offset = set->header->sections[i].offset;
		size = set->header->sections[i + 1].offset - offset;

		switch (set->header->sections[i].type) {
		case RAZOR_BUCKETS:
			set->buckets.data = (void *) set->header + offset;
			set->buckets.size = size;
			set->buckets.alloc = size;
			break;
		case RAZOR_STRINGS:
			set->string_pool.data = (void *) set->header + offset;
			set->string_pool.size = size;
			set->string_pool.alloc = size;
			break;
		case RAZOR_PACKAGES:
			set->packages.data = (void *) set->header + offset;
			set->packages.size = size;
			set->packages.size = size;
			break;
		case RAZOR_REQUIRES:
			set->requires.data = (void *) set->header + offset;
			set->requires.size = size;
			set->requires.size = size;
			break;
		case RAZOR_PROVIDES:
			set->provides.data = (void *) set->header + offset;
			set->provides.size = size;
			set->provides.size = size;
			break;
		}
	}
	close(fd);

	return set;
}

void
razor_set_destroy(struct razor_set *set)
{
	unsigned int size;
	int i;

	if (set->header) {
		for (i = 0; set->header->sections[i].type; i++)
			;
		size = set->header->sections[i].type;
		munmap(set->header, size);
	} else {
		free(set->buckets.data);
		free(set->string_pool.data);
		free(set->packages.data);
		free(set->requires.data);
		free(set->provides.data);
	}

	free(set);
}

static int
razor_set_write(struct razor_set *set, const char *filename)
{
	char data[4096];
	struct razor_set_header *header = (struct razor_set_header *) data;
	int fd, pool_size, packages_size, requires_size, provides_size;

	/* Align these to pages sizes */
	pool_size = (set->string_pool.size + 4095) & ~4095;
	packages_size = (set->packages.size + 4095) & ~4095;
	requires_size = (set->requires.size + 4095) & ~4095;
	provides_size = (set->provides.size + 4095) & ~4095;

	memset(data, 0, sizeof data);
	header->magic = RAZOR_MAGIC;
	header->version = RAZOR_VERSION;

	header->sections[0].type = RAZOR_BUCKETS;
	header->sections[0].offset = sizeof data;

	header->sections[1].type = RAZOR_STRINGS;
	header->sections[1].offset =
		header->sections[0].offset + set->buckets.alloc;

	header->sections[2].type = RAZOR_PACKAGES;
	header->sections[2].offset =
		header->sections[1].offset + pool_size;

	header->sections[3].type = RAZOR_REQUIRES;
	header->sections[3].offset =
		header->sections[2].offset + packages_size;

	header->sections[4].type = RAZOR_PROVIDES;
	header->sections[4].offset =
		header->sections[3].offset + requires_size;

	header->sections[5].type = 0;
	header->sections[5].offset =
		header->sections[4].offset + provides_size;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	write_to_fd(fd, data, sizeof data);
	write_to_fd(fd, set->buckets.data, set->buckets.alloc);
	write_to_fd(fd, set->string_pool.data, pool_size);
	write_to_fd(fd, set->packages.data, packages_size);
	write_to_fd(fd, set->requires.data, requires_size);
	write_to_fd(fd, set->provides.data, provides_size);

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

static unsigned long
razor_set_add_package(struct razor_set *set,
		      unsigned long name, unsigned long version)
{
	struct razor_package *p;

	p = array_add(&set->packages, sizeof *p);

	p->name = name;
	p->version = version;

	return p - (struct razor_package *) set->packages.data;
}

static unsigned long
razor_set_add_requires(struct razor_set *set,
		       unsigned long name, unsigned long version)
{
	struct razor_property *p;

	p = array_add(&set->requires, sizeof *p);

	p->name = name;
	p->version = version;

	return p - (struct razor_property *) set->requires.data;
}

static unsigned long
razor_set_add_provides(struct razor_set *set,
		       unsigned long name, unsigned long version)
{
	struct razor_property *p;

	p = array_add(&set->provides, sizeof *p);

	p->name = name;
	p->version = version;

	return p - (struct razor_property *) set->provides.data;
}

unsigned long
razor_set_tokenize(struct razor_set *set, const char *string)
{
	unsigned long token;

	token = razor_set_lookup(set, string);
	if (token != 0)
		return token;

	return razor_set_insert(set, string);
}

struct import_context {
	struct razor_set *set;
	struct array requires;
	struct array provides;
	unsigned long package;
};

static void
parse_package(struct import_context *ctx, const char **atts, void *data)
{
	unsigned long name = 0, version = 0;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = razor_set_tokenize(ctx->set, atts[i + 1]);
		else if (strcmp(atts[i], "version") == 0)
			version = razor_set_tokenize(ctx->set, atts[i + 1]);
	}

	if (name == 0 || version == 0) {
		fprintf(stderr, "invalid package tag, "
			"missing name or version attributes\n");
		return;
	}

	ctx->package = razor_set_add_package(ctx->set, name, version);

	return;
}

static void
parse_property(struct import_context *ctx, const char **atts, void *data)
{
	unsigned long name = 0, version = 0;
	struct razor_property *p;
	struct array *array = data;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = razor_set_tokenize(ctx->set, atts[i + 1]);
		if (strcmp(atts[i], "version") == 0)
			version = razor_set_tokenize(ctx->set, atts[i + 1]);
	}
	
	if (name == 0) {
		fprintf(stderr, "invalid tag, missing name attribute\n");
		return;
	}

	p = array_add(array, sizeof *p);
	p->name = name;
	p->version = version;
	p->packages = ctx->package;
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
		ctx->package = 0;
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
razor_set_prepare_import(struct razor_set *set, struct import_context *ctx)
{
	memset(ctx, 0, sizeof *ctx);
	ctx->set = set;
}

static int
razor_set_import(struct import_context *ctx, const char *filename)
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

static struct razor_set *qsort_set;

static int
compare_packages(const void *p1, const void *p2)
{
	const struct razor_package *pkg1 = p1, *pkg2 = p2;
	char *pool = qsort_set->string_pool.data;

	return strcmp(&pool[pkg1->name], &pool[pkg2->name]);
}

static int
compare_properties(const void *p1, const void *p2)
{
	const struct razor_property *prop1 = p1, *prop2 = p2;
	char *pool = qsort_set->string_pool.data;

	return strcmp(&pool[prop1->name], &pool[prop2->name]);
}

static void
uniqueify_properties(struct array *in, struct array *out)
{
	struct razor_property *p, *q, *end;

	qsort(in->data, in->size / sizeof(struct razor_property),
	      sizeof(struct razor_property), compare_properties);

	q = NULL;
	end = in->data + in->size;
	for (p = in->data; p < end && p->name; p++) {
		if (q == NULL ||
		    p->name != q->name || p->version != q->version) {
			q = array_add(out, sizeof *q);
			q->name = p->name;
			q->version = p->version;

		}
	}
}

static void
razor_set_finish_import(struct import_context *ctx)
{
	qsort_set = ctx->set;
	qsort(ctx->set->packages.data,
	      ctx->set->packages.size / sizeof(struct razor_package),
	      sizeof(struct razor_package), compare_packages);

	uniqueify_properties(&ctx->requires, &ctx->set->requires);
	uniqueify_properties(&ctx->provides, &ctx->set->provides);

	free(ctx->requires.data);
	free(ctx->provides.data);

	fprintf(stderr, "parsed %d requires, %d unique\n",
		ctx->requires.size / sizeof(struct razor_property),
		ctx->set->requires.size / sizeof(struct razor_property));
	fprintf(stderr, "parsed %d provides, %d unique\n",
		ctx->provides.size / sizeof(struct razor_property),
		ctx->set->provides.size / sizeof(struct razor_property));
}


void
razor_set_list(struct razor_set *set)
{
	struct razor_package *p, *end;
	char *pool;

	pool = set->string_pool.data;
	end = set->packages.data + set->packages.size;
	for (p = set->packages.data; p < end && p->name; p++)
		printf("%s %s\n", &pool[p->name], &pool[p->version]);
}

void
razor_set_list_requires(struct razor_set *set)
{
	struct razor_property *p, *end;
	char *pool;

	pool = set->string_pool.data;
	end = set->requires.data + set->requires.size;
	for (p = set->requires.data; p < end && p->name; p++)
		printf("%s %s\n", &pool[p->name], &pool[p->version]);
}

void
razor_set_list_provides(struct razor_set *set)
{
	struct razor_property *p, *end;
	char *pool;

	pool = set->string_pool.data;
	end = set->provides.data + set->provides.size;
	for (p = set->provides.data; p < end && p->name; p++)
		printf("%s %s\n", &pool[p->name], &pool[p->version]);
}

void
razor_set_info(struct razor_set *set)
{
	unsigned int offset, size;
	int i;

	for (i = 0; i < set->header->sections[i].type; i++) {
		offset = set->header->sections[i].offset;
		size = set->header->sections[i + 1].offset - offset;

		switch (set->header->sections[i].type) {
		case RAZOR_BUCKETS:
			printf("bucket section:\t\t%dkb\n", size / 1024);
			break;
		case RAZOR_STRINGS:
			printf("string pool:\t\t%dkb\n", size / 1024);
			break;
		case RAZOR_PACKAGES:
			printf("package section:\t%dkb\n", size / 1024);
			break;
		case RAZOR_REQUIRES:
			printf("requires section:\t%dkb\n", size / 1024);
			break;
		case RAZOR_PROVIDES:
			printf("provides section:\t%dkb\n", size / 1024);
			break;
		}
	}
}

static int
usage(void)
{
	printf("usage: razor [ import FILES | lookup <key> | "
	       "list | list-requires | list-provides | info ]\n");
	exit(1);
}

static const char repo_filename[] = "system.repo";

int
main(int argc, char *argv[])
{
	int i;
	struct razor_set *set;
	struct stat statbuf;
	struct import_context ctx;

	if (argc < 2) {
		usage();
	} else if (strcmp(argv[1], "import") == 0) {
		if (stat("set", &statbuf) && mkdir("set", 0777)) {
			fprintf(stderr, "could not create directory 'set'\n");
			exit(-1);
		}
			
		set = razor_set_create();

		razor_set_prepare_import(set, &ctx);

		for (i = 2; i < argc; i++) {
			if (razor_set_import(&ctx, argv[i]) < 0) {
				fprintf(stderr, "failed to import %s\n",
					argv[i]);
				exit(-1);
			}
		}

		razor_set_finish_import(&ctx);

		/* FIXME: We add a sentinel package here, but we
		 * should probably just have a size field in the
		 * header section. */
		razor_set_add_package(set, 0, 0);
		razor_set_add_requires(set, 0, 0);
		razor_set_add_provides(set, 0, 0);

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
		razor_set_list_requires(set);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "list-provides") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_list_provides(set);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "info") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_info(set);
		razor_set_destroy(set);
	} else {
		usage();
	}

	return 0;
}
