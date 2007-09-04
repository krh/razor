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

struct hashtable_header {
	unsigned int magic;
	unsigned int version;
	struct { unsigned int type, offset; } sections[0];
};

#define HASHTABLE_MAGIC 0x7a7a7a7a
#define HASHTABLE_VERSION 1
#define HASHTABLE_BUCKETS 1
#define HASHTABLE_STRINGS 2
#define HASHTABLE_PACKAGES 3

struct package {
	unsigned long name;
	unsigned long version;
};

struct hashtable {
	unsigned long *buckets;
	int bucket_count, bucket_alloc;
	char *string_pool;
	int pool_size, pool_alloc;
	struct hashtable_header *header;

	struct package *packages;
	int package_count, package_alloc;
};

static void *
zalloc(size_t size)
{
	void *p;

	p = malloc(size);
	memset(p, 0, size);

	return p;
}

struct hashtable *
hashtable_create(void)
{
	struct hashtable *ht;

	ht = zalloc(sizeof *ht);
	ht->buckets = zalloc(4096 * sizeof *ht->buckets);
	ht->bucket_count = 0;
	ht->bucket_alloc = 4096;

	ht->string_pool = zalloc(4096);
	ht->pool_size = 1;
	ht->pool_alloc = 4096;

	ht->packages = zalloc(4096 * sizeof *ht->packages);
	ht->package_count = 0;
	ht->package_alloc = 4096;

	return ht;
}

struct hashtable *
hashtable_create_from_file(const char *filename)
{
	struct hashtable *ht;
	struct stat stat;
	unsigned int size, offset;
	int fd, i;

	ht = zalloc(sizeof *ht);
	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return NULL;
	ht->header = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (ht->header == MAP_FAILED) {
		free(ht);
		return NULL;
	}

	for (i = 0; i < ht->header->sections[i].type; i++) {
		offset = ht->header->sections[i].offset;
		size = ht->header->sections[i + 1].offset - offset;

		switch (ht->header->sections[i].type) {
		case HASHTABLE_BUCKETS:
			ht->buckets = (void *) ht->header + offset;
			ht->bucket_count = size / sizeof *ht->buckets;
			ht->bucket_alloc = ht->bucket_count;
			break;
		case HASHTABLE_STRINGS:
			ht->string_pool = (void *) ht->header + offset;
			ht->pool_size = size;
			ht->pool_alloc = size;
			break;
		case HASHTABLE_PACKAGES:
			ht->packages = (void *) ht->header + offset;
			ht->package_count = size / sizeof *ht->packages;
			ht->package_alloc = size / sizeof *ht->packages;
			break;
		}
	}
	close(fd);

	return ht;
}

void
hashtable_destroy(struct hashtable *ht)
{
	unsigned int size;
	int i;

	if (ht->header) {
		for (i = 0; ht->header->sections[i].type; i++)
			;
		size = ht->header->sections[i].type;
		munmap(ht->header, size);
	} else {
		free(ht->buckets);
		free(ht->string_pool);
	}

	free(ht);
}

static int
hashtable_write(struct hashtable *ht, const char *filename)
{
	char data[4096];
	struct hashtable_header *header = (struct hashtable_header *) data;
	int fd, pool_size, package_size;

	/* Align these to pages sizes */
	pool_size = (ht->pool_size + 4095) & ~4095;
	package_size =
		(ht->package_alloc * sizeof *ht->packages + 4095) & ~4095;

	memset(data, 0, sizeof data);
	header->magic = HASHTABLE_MAGIC;
	header->version = HASHTABLE_VERSION;

	header->sections[0].type = HASHTABLE_BUCKETS;
	header->sections[0].offset = sizeof data;

	header->sections[1].type = HASHTABLE_STRINGS;
	header->sections[1].offset = header->sections[0].offset +
		ht->bucket_alloc * sizeof *ht->buckets;

	header->sections[2].type = HASHTABLE_PACKAGES;
	header->sections[2].offset = header->sections[1].offset + pool_size;

	header->sections[3].type = 0;
	header->sections[3].offset = header->sections[2].offset + package_size;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	write_to_fd(fd, data, sizeof data);
	write_to_fd(fd, ht->buckets, ht->bucket_alloc * sizeof *ht->buckets);
	write_to_fd(fd, ht->string_pool, pool_size);
	write_to_fd(fd, ht->packages, package_size);

	return 0;
}

static unsigned int
hash_string(const char *key)
{
	const char *p;
	unsigned int hash = 0;

	for (p = key; *p; p++)
		hash = (hash << 2) ^ *p;

	return hash;
}

unsigned long
hashtable_lookup(struct hashtable *ht, const char *key)
{
	unsigned int start;
	unsigned int mask;
	unsigned long value;
	int i;

	mask = ht->bucket_alloc - 1;
	start = hash_string(key) & mask;
	i = start;
	do {
		value = ht->buckets[i];

		if (value == 0)
			return 0;

		if (strcmp(key, &ht->string_pool[value]) == 0)
			return value;

		i = (i + 1) & mask;
	} while (i != start);

	return 0;
}

static unsigned long
add_to_string_pool(struct hashtable *ht, const char *key)
{
	int len, alloc;
	char *pool;
	unsigned long value;

	len = strlen(key) + 1;
	alloc = ht->pool_alloc;
	while (alloc < ht->pool_size + len)
		alloc *= 2;
	if (ht->pool_alloc < alloc) {
		pool = realloc(ht->string_pool, alloc);
		if (pool == NULL)
			return 0;
		ht->string_pool = pool;
		ht->pool_alloc = alloc;
	}

	memcpy(ht->string_pool + ht->pool_size, key, len);
	value = ht->pool_size;
	ht->pool_size += len;

	return value;
}

static void
do_insert(struct hashtable *ht, unsigned long value)
{
	unsigned int mask;
	const char *key;
	int i, start;

	key = &ht->string_pool[value];
	mask = ht->bucket_alloc - 1;
	start = hash_string(key) & mask;
	i = start;
	do {
		if (ht->buckets[i] == 0) {
			ht->buckets[i] = value;
			break;
		}
		i = (i + 1) & mask;
	} while (i != start);
}

unsigned long
hashtable_insert(struct hashtable *ht, const char *key)
{
	unsigned long value, *buckets, *old_buckets;
	int i, alloc, old_alloc;

	alloc = ht->bucket_alloc;
	while (alloc < 4 * ht->bucket_count)
		alloc *= 2;

	if (alloc != ht->bucket_alloc) {
		buckets = zalloc(alloc * sizeof *ht->buckets);
		if (buckets == NULL)
			return 0;
		old_buckets = ht->buckets;
		ht->buckets = buckets;
		old_alloc = ht->bucket_alloc;
		ht->bucket_alloc = alloc;
		
		for (i = 0; i < old_alloc; i++) {
			value = old_buckets[i];
			if (value != 0)
				do_insert(ht, value);
		}
		free(old_buckets);
	}

	value = add_to_string_pool(ht, key);
	do_insert (ht, value);
	ht->bucket_count++;

	return value;
}

static unsigned long
hashtable_add_package(struct hashtable *ht,
		      unsigned long name, unsigned long version)
{
	struct package *packages;
	int alloc;

	alloc = ht->package_alloc;
	while (alloc < ht->package_count + 1)
		alloc *= 2;
	if (ht->package_alloc < alloc) {
		packages = realloc(ht->packages, alloc * sizeof ht->packages);
		if (packages == NULL)
			return 0;
		ht->packages = packages;
		ht->package_alloc = alloc;
	}

	ht->packages[ht->package_count].name = name;
	ht->packages[ht->package_count].version = version;
	ht->package_count++;

	return 0;
}


struct razor_context {
	struct hashtable *global_ht;
};

struct razor_context *
razor_context_create (void)
{
	struct razor_context *ctx;

	ctx = malloc(sizeof *ctx);
	ctx->global_ht = hashtable_create();

	return ctx;
}

struct razor_context *
razor_context_create_from_file (const char *filename)
{
	struct razor_context *ctx;

	ctx = malloc(sizeof *ctx);
	ctx->global_ht = hashtable_create_from_file(filename);

	return ctx;
}

unsigned long
razor_context_tokenize(struct razor_context *ctx, const char *string)
{
	unsigned long token;

	token = hashtable_lookup(ctx->global_ht, string);
	if (token != 0)
		return token;

	return hashtable_insert(ctx->global_ht, string);
}

static struct hashtable *qsort_ht;

static int
compare_packages(const void *p1, const void *p2)
{
	const struct package *pkg1 = p1, *pkg2 = p2;

	return strcmp(&qsort_ht->string_pool[pkg1->name],
		      &qsort_ht->string_pool[pkg2->name]);
}

static void
razor_context_sort(struct razor_context *ctx)
{
	struct hashtable *ht = ctx->global_ht;

	qsort_ht = ht;
	qsort(ht->packages, ht->package_count, sizeof *ht->packages,
	      compare_packages);
}

struct razor_set {
	struct razor_context *ctx;
};

struct parsing_context {
	struct razor_context *ctx;
};

static void
parse_package(struct parsing_context *ctx, const char **atts)
{
	unsigned long name, version;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = razor_context_tokenize(ctx->ctx, atts[i + 1]);
		else if (strcmp(atts[i], "version") == 0)
			version = razor_context_tokenize(ctx->ctx, atts[i + 1]);
	}

	if (name == 0 || version == 0) {
		fprintf(stderr, "invalid package tag, "
			"missing name or version attributes\n");
		return;
	}

	hashtable_add_package(ctx->ctx->global_ht, name, version);
}

static void
start_element(void *data, const char *name, const char **atts)
{
	struct parsing_context *ctx = data;
	int i;

	if (strcmp(name, "package") == 0)
		parse_package(ctx, atts);

	for (i = 0; atts[i]; i += 2)
		razor_context_tokenize(ctx->ctx, atts[i + 1]);
}

static void
end_element (void *data, const char *name)
{
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

static int
razor_context_read_file(struct razor_context *ctx, const char *filename)
{
	SHA_CTX sha1;
	XML_Parser parser;
	struct parsing_context pctx;
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
	pctx.ctx = ctx;
	XML_SetUserData(parser, &pctx);
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

int
razor_context_write(struct razor_context *ctx, const char *filename)
{
	return hashtable_write(ctx->global_ht, filename);
}

void
razor_context_list_packages(struct razor_context *ctx)
{
	int i;
	struct hashtable *ht = ctx->global_ht;
	struct package *p;

	p = ht->packages;
	for (i = 0; i < ht->package_count && p->name; i++, p++) {
		printf("%s %s\n",
		       &ht->string_pool[p->name],
		       &ht->string_pool[p->version]);
	}
}

void
razor_context_info(struct razor_context *ctx)
{
	struct hashtable *ht = ctx->global_ht;
	unsigned int offset, size;
	int i;

	for (i = 0; i < ht->header->sections[i].type; i++) {
		offset = ht->header->sections[i].offset;
		size = ht->header->sections[i + 1].offset - offset;

		switch (ht->header->sections[i].type) {
		case HASHTABLE_BUCKETS:
			printf("bucket section:\t\t%dkb\n", size / 1024);
			break;
		case HASHTABLE_STRINGS:
			printf("string pool:\t\t%dkb\n", size / 1024);
			break;
		case HASHTABLE_PACKAGES:
			printf("package section:\t%dkb\n", size / 1024);
			break;
		}
	}

}

void
razor_context_destroy(struct razor_context *ctx)
{
	hashtable_destroy(ctx->global_ht);
	free(ctx);
}

static int
usage(void)
{
	printf("usage: razor [ import FILES | lookup <key> | list | info ]\n");
	exit(1);
}

static const char repo_filename[] = "system.repo";

int
main(int argc, char *argv[])
{
	int i;
	struct razor_context *ctx;
	struct stat statbuf;

	if (argc < 2) {
		usage();
	} else if (strcmp(argv[1], "import") == 0) {
		if (stat("set", &statbuf) && mkdir("set", 0777)) {
			fprintf(stderr, "could not create directory 'set'\n");
			exit(-1);
		}
			
		ctx = razor_context_create();

		for (i = 2; i < argc; i++) {
			if (razor_context_read_file(ctx, argv[i]) < 0) {
				fprintf(stderr, "failed to import %s\n",
					argv[i]);
				exit(-1);
			}
		}

		razor_context_sort(ctx);

		printf("number of buckets: %d\n",
		       ctx->global_ht->bucket_count);
		printf("bucket allocation: %d\n",
		       ctx->global_ht->bucket_alloc);
		printf("pool size: %d\n", ctx->global_ht->pool_size);
		printf("pool allocation: %d\n", ctx->global_ht->pool_alloc);

		razor_context_write(ctx, repo_filename);

		razor_context_destroy(ctx);
	} else if (strcmp(argv[1], "lookup") == 0) {
		ctx = razor_context_create_from_file(repo_filename);
		printf("%s is %lu\n", argv[2],
		       hashtable_lookup(ctx->global_ht, argv[2]));
		razor_context_destroy(ctx);
	} else if (strcmp(argv[1], "list") == 0) {
		ctx = razor_context_create_from_file(repo_filename);
		razor_context_list_packages(ctx);
		razor_context_destroy(ctx);
	} else if (strcmp(argv[1], "info") == 0) {
		ctx = razor_context_create_from_file(repo_filename);
		razor_context_info(ctx);
		razor_context_destroy(ctx);
	} else {
		usage();
	}

	return 0;
}
