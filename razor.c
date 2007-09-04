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

struct razor_package {
	unsigned long name;
	unsigned long version;
};

struct razor_set {
	unsigned long *buckets;
	int bucket_count, bucket_alloc;
	char *string_pool;
	int pool_size, pool_alloc;
	struct razor_set_header *header;

	struct razor_package *packages;
	int package_count, package_alloc;
};

struct razor_set *
razor_set_create(void)
{
	struct razor_set *set;

	set = zalloc(sizeof *set);
	set->buckets = zalloc(4096 * sizeof *set->buckets);
	set->bucket_count = 0;
	set->bucket_alloc = 4096;

	set->string_pool = zalloc(4096);
	set->pool_size = 1;
	set->pool_alloc = 4096;

	set->packages = zalloc(4096 * sizeof *set->packages);
	set->package_count = 0;
	set->package_alloc = 4096;

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
			set->buckets = (void *) set->header + offset;
			set->bucket_count = size / sizeof *set->buckets;
			set->bucket_alloc = set->bucket_count;
			break;
		case RAZOR_STRINGS:
			set->string_pool = (void *) set->header + offset;
			set->pool_size = size;
			set->pool_alloc = size;
			break;
		case RAZOR_PACKAGES:
			set->packages = (void *) set->header + offset;
			set->package_count = size / sizeof *set->packages;
			set->package_alloc = size / sizeof *set->packages;
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
		free(set->buckets);
		free(set->string_pool);
	}

	free(set);
}

static int
razor_set_write(struct razor_set *set, const char *filename)
{
	char data[4096];
	struct razor_set_header *header = (struct razor_set_header *) data;
	int fd, pool_size, package_size;

	/* Align these to pages sizes */
	pool_size = (set->pool_size + 4095) & ~4095;
	package_size =
		(set->package_alloc * sizeof *set->packages + 4095) & ~4095;

	memset(data, 0, sizeof data);
	header->magic = RAZOR_MAGIC;
	header->version = RAZOR_VERSION;

	header->sections[0].type = RAZOR_BUCKETS;
	header->sections[0].offset = sizeof data;

	header->sections[1].type = RAZOR_STRINGS;
	header->sections[1].offset = header->sections[0].offset +
		set->bucket_alloc * sizeof *set->buckets;

	header->sections[2].type = RAZOR_PACKAGES;
	header->sections[2].offset = header->sections[1].offset + pool_size;

	header->sections[3].type = 0;
	header->sections[3].offset = header->sections[2].offset + package_size;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	write_to_fd(fd, data, sizeof data);
	write_to_fd(fd, set->buckets, set->bucket_alloc * sizeof *set->buckets);
	write_to_fd(fd, set->string_pool, pool_size);
	write_to_fd(fd, set->packages, package_size);

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
razor_set_lookup(struct razor_set *set, const char *key)
{
	unsigned int start;
	unsigned int mask;
	unsigned long value;
	int i;

	mask = set->bucket_alloc - 1;
	start = hash_string(key) & mask;
	i = start;
	do {
		value = set->buckets[i];

		if (value == 0)
			return 0;

		if (strcmp(key, &set->string_pool[value]) == 0)
			return value;

		i = (i + 1) & mask;
	} while (i != start);

	return 0;
}

static unsigned long
add_to_string_pool(struct razor_set *set, const char *key)
{
	int len, alloc;
	char *pool;
	unsigned long value;

	len = strlen(key) + 1;
	alloc = set->pool_alloc;
	while (alloc < set->pool_size + len)
		alloc *= 2;
	if (set->pool_alloc < alloc) {
		pool = realloc(set->string_pool, alloc);
		if (pool == NULL)
			return 0;
		set->string_pool = pool;
		set->pool_alloc = alloc;
	}

	memcpy(set->string_pool + set->pool_size, key, len);
	value = set->pool_size;
	set->pool_size += len;

	return value;
}

static void
do_insert(struct razor_set *set, unsigned long value)
{
	unsigned int mask;
	const char *key;
	int i, start;

	key = &set->string_pool[value];
	mask = set->bucket_alloc - 1;
	start = hash_string(key) & mask;
	i = start;
	do {
		if (set->buckets[i] == 0) {
			set->buckets[i] = value;
			break;
		}
		i = (i + 1) & mask;
	} while (i != start);
}

unsigned long
razor_set_insert(struct razor_set *set, const char *key)
{
	unsigned long value, *buckets, *old_buckets;
	int i, alloc, old_alloc;

	alloc = set->bucket_alloc;
	while (alloc < 4 * set->bucket_count)
		alloc *= 2;

	if (alloc != set->bucket_alloc) {
		buckets = zalloc(alloc * sizeof *set->buckets);
		if (buckets == NULL)
			return 0;
		old_buckets = set->buckets;
		set->buckets = buckets;
		old_alloc = set->bucket_alloc;
		set->bucket_alloc = alloc;
		
		for (i = 0; i < old_alloc; i++) {
			value = old_buckets[i];
			if (value != 0)
				do_insert(set, value);
		}
		free(old_buckets);
	}

	value = add_to_string_pool(set, key);
	do_insert (set, value);
	set->bucket_count++;

	return value;
}

static unsigned long
razor_set_add_package(struct razor_set *set,
		      unsigned long name, unsigned long version)
{
	struct razor_package *packages;
	int alloc;

	/* FIXME: make 0 an illegal pkgs number. */
	alloc = set->package_alloc;
	while (alloc < set->package_count + 1)
		alloc *= 2;
	if (set->package_alloc < alloc) {
		packages = realloc(set->packages, alloc * sizeof set->packages);
		if (packages == NULL)
			return 0;
		set->packages = packages;
		set->package_alloc = alloc;
	}

	set->packages[set->package_count].name = name;
	set->packages[set->package_count].version = version;

	return set->package_count++;
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

static struct razor_set *qsort_set;

static int
compare_packages(const void *p1, const void *p2)
{
	const struct razor_package *pkg1 = p1, *pkg2 = p2;

	return strcmp(&qsort_set->string_pool[pkg1->name],
		      &qsort_set->string_pool[pkg2->name]);
}

static void
razor_set_sort(struct razor_set *set)
{
	qsort_set = set;
	qsort(set->packages, set->package_count, sizeof *set->packages,
	      compare_packages);
}

struct parsing_context {
	struct razor_set *set;
	int pkg_id;
};

static void
parse_package(struct parsing_context *ctx, const char **atts)
{
	unsigned long name, version;
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

	ctx->pkg_id = razor_set_add_package(ctx->set, name, version);

	return;
}

static void
start_element(void *data, const char *name, const char **atts)
{
	struct parsing_context *ctx = data;
	int i;

	if (strcmp(name, "package") == 0)
		parse_package(ctx, atts);

	for (i = 0; atts[i]; i += 2)
		razor_set_tokenize(ctx->set, atts[i + 1]);
}

static void
end_element (void *data, const char *name)
{
	struct parsing_context *ctx = data;

	if (strcmp(name, "package") == 0)
		ctx->pkg_id = 0;
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
razor_set_import(struct razor_set *set, const char *filename)
{
	SHA_CTX sha1;
	XML_Parser parser;
	struct parsing_context ctx;
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
	ctx.set = set;
	XML_SetUserData(parser, &ctx);
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

void
razor_set_list(struct razor_set *set)
{
	int i;
	struct razor_package *p;

	p = set->packages;
	for (i = 0; i < set->package_count && p->name; i++, p++) {
		printf("%s %s\n",
		       &set->string_pool[p->name],
		       &set->string_pool[p->version]);
	}
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
		}
	}
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
	struct razor_set *set;
	struct stat statbuf;

	if (argc < 2) {
		usage();
	} else if (strcmp(argv[1], "import") == 0) {
		if (stat("set", &statbuf) && mkdir("set", 0777)) {
			fprintf(stderr, "could not create directory 'set'\n");
			exit(-1);
		}
			
		set = razor_set_create();

		for (i = 2; i < argc; i++) {
			if (razor_set_import(set, argv[i]) < 0) {
				fprintf(stderr, "failed to import %s\n",
					argv[i]);
				exit(-1);
			}
		}

		razor_set_sort(set);

		printf("number of buckets: %d\n",
		       set->bucket_count);
		printf("bucket allocation: %d\n",
		       set->bucket_alloc);
		printf("pool size: %d\n", set->pool_size);
		printf("pool allocation: %d\n", set->pool_alloc);

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
	} else if (strcmp(argv[1], "info") == 0) {
		set = razor_set_open(repo_filename);
		razor_set_info(set);
		razor_set_destroy(set);
	} else {
		usage();
	}

	return 0;
}
