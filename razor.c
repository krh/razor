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
#include <ctype.h>
#include <fnmatch.h>

#include "razor.h"

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

#define RAZOR_ENTRY_LAST	0x80000000ul
#define RAZOR_IMMEDIATE		0x80000000ul
#define RAZOR_ENTRY_MASK	0x00fffffful

#define RAZOR_STRING_POOL 0
#define RAZOR_PACKAGES 1
#define RAZOR_REQUIRES 2
#define RAZOR_PROVIDES 3
#define RAZOR_FILES 4
#define RAZOR_PACKAGE_POOL 5
#define RAZOR_REQUIRES_POOL 6
#define RAZOR_PROVIDES_POOL 7
#define RAZOR_FILE_POOL 8

struct razor_package {
	unsigned long name;
	unsigned long version;
	unsigned long requires;
	unsigned long provides;
	unsigned long files;
};

struct razor_property {
	unsigned long name;
	unsigned long version;
	unsigned long packages;
};

struct razor_entry {
	unsigned long name;
	unsigned long start;
	unsigned long packages;
};

struct razor_set {
	struct array string_pool;
 	struct array packages;
 	struct array requires;
 	struct array provides;
 	struct array files;
	struct array package_pool;
 	struct array requires_pool;
 	struct array provides_pool;
 	struct array file_pool;
	struct razor_set_header *header;
};

struct import_entry {
	unsigned long package;
	char *name;
};

struct import_directory {
	unsigned long name, count;
	struct array files;
	struct array packages;
	struct import_directory *last;
};

struct import_property_context {
	struct array *all;
	struct array package;
};

struct razor_importer {
	struct razor_set *set;
	struct array buckets;
	struct import_property_context requires;
	struct import_property_context provides;
	struct razor_package *package;
	struct array files;
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

static void *
zalloc(size_t size)
{
	void *p;

	p = malloc(size);
	memset(p, 0, size);

	return p;
}

struct razor_set_section razor_sections[] = {
	{ RAZOR_STRING_POOL,	offsetof(struct razor_set, string_pool) },
	{ RAZOR_PACKAGES,	offsetof(struct razor_set, packages) },
	{ RAZOR_REQUIRES,	offsetof(struct razor_set, requires) },
	{ RAZOR_PROVIDES,	offsetof(struct razor_set, provides) },
	{ RAZOR_FILES,		offsetof(struct razor_set, files) },
	{ RAZOR_PACKAGE_POOL,	offsetof(struct razor_set, package_pool) },
	{ RAZOR_REQUIRES_POOL,	offsetof(struct razor_set, requires_pool) },
	{ RAZOR_PROVIDES_POOL,	offsetof(struct razor_set, provides_pool) },
	{ RAZOR_FILE_POOL,	offsetof(struct razor_set, file_pool) },
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
	} else {
		for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
			a = (void *) set + razor_sections[i].offset;
			free(a->data);
		}
	}

	free(set);
}

int
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

static unsigned long
razor_importer_lookup(struct razor_importer *importer, const char *key)
{
	unsigned int mask, start, i;
	unsigned long *b;
	char *pool;

	pool = importer->set->string_pool.data;
	mask = importer->buckets.alloc - 1;
	start = hash_string(key) * sizeof(unsigned long);

	for (i = 0; i < importer->buckets.alloc; i += sizeof *b) {
		b = importer->buckets.data + ((start + i) & mask);

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
add_to_property_pool(struct array *pool, struct array *properties)
{
	unsigned long  *p;

	p = array_add(properties, sizeof *p);
	*p = ~0ul;
	p = array_add(pool, properties->size);
	memcpy(p, properties->data, properties->size);

	return p - (unsigned long *) pool->data;
}

static void
do_insert(struct razor_importer *importer, unsigned long value)
{
	unsigned int mask, start, i;
	unsigned long *b;
	const char *key;

	key = (char *) importer->set->string_pool.data + value;
	mask = importer->buckets.alloc - 1;
	start = hash_string(key) * sizeof(unsigned long);

	for (i = 0; i < importer->buckets.alloc; i += sizeof *b) {
		b = importer->buckets.data + ((start + i) & mask);
		if (*b == 0) {
			*b = value;
			break;
		}
	}
}

static unsigned long
razor_importer_insert(struct razor_importer *importer, const char *key)
{
	unsigned long value, *buckets, *b, *end;
	int alloc;

	alloc = importer->buckets.alloc;
	array_add(&importer->buckets, 4 * sizeof *buckets);
	if (alloc != importer->buckets.alloc) {
		end = importer->buckets.data + alloc;
		memset(end, 0, importer->buckets.alloc - alloc);
		for (b = importer->buckets.data; b < end; b++) {
			value = *b;
			if (value != 0) {
				*b = 0;
				do_insert(importer, value);
			}
		}
	}

	value = add_to_string_pool(importer->set, key);
	do_insert (importer, value);

	return value;
}

static unsigned long
razor_importer_tokenize(struct razor_importer *importer, const char *string)
{
	unsigned long token;

	if (string == NULL)
		return razor_importer_tokenize(importer, "");

	token = razor_importer_lookup(importer, string);
	if (token != 0)
		return token;

	return razor_importer_insert(importer, string);
}

void
razor_importer_begin_package(struct razor_importer *importer,
			     const char *name, const char *version)
{
	struct razor_package *p;

	p = array_add(&importer->set->packages, sizeof *p);
	p->name = razor_importer_tokenize(importer, name);
	p->version = razor_importer_tokenize(importer, version);

	importer->package = p;
	array_init(&importer->requires.package);
	array_init(&importer->provides.package);
}

void
razor_importer_finish_package(struct razor_importer *importer)
{
	struct razor_package *p;

	p = importer->package;
	p->requires = add_to_property_pool(&importer->set->requires_pool,
					   &importer->requires.package);
	p->provides = add_to_property_pool(&importer->set->provides_pool,
					   &importer->provides.package);

	array_release(&importer->requires.package);
	array_release(&importer->provides.package);
}

static void
razor_importer_add_property(struct razor_importer *importer,
			    struct import_property_context *pctx,
			    const char *name, const char *version)
{
	struct razor_property *p;
	unsigned long *r;

	p = array_add(pctx->all, sizeof *p);
	p->name = razor_importer_tokenize(importer, name);
	p->version = razor_importer_tokenize(importer, version);
	p->packages = importer->package -
		(struct razor_package *) importer->set->packages.data;

	r = array_add(&pctx->package, sizeof *r);
	*r = p - (struct razor_property *) pctx->all->data;
}

void
razor_importer_add_requires(struct razor_importer *importer,
			    const char *name, const char *version)
{
	razor_importer_add_property(importer,
				    &importer->requires, name, version);
}

void
razor_importer_add_provides(struct razor_importer *importer,
			    const char *name, const char *version)
{
	razor_importer_add_property(importer,
				    &importer->provides, name, version);
}

void
razor_importer_add_file(struct razor_importer *importer, const char *name)
{
	struct import_entry *e;

	e = array_add(&importer->files, sizeof *e);

	e->package = importer->package -
		(struct razor_package *) importer->set->packages.data;
	e->name = strdup(name);
}

struct razor_importer *
razor_importer_new(void)
{
	struct razor_importer *importer;

	importer = zalloc(sizeof *importer);
	importer->set = razor_set_create();
	importer->requires.all = &importer->set->requires;
	importer->provides.all = &importer->set->provides;

	return importer;
}

typedef int (*compare_with_data_func_t)(const void *p1,
					const void *p,
					void *data);

struct qsort_context {
	size_t size;
	compare_with_data_func_t compare;
	void *data;
};

static void
qsort_swap(void *p1, void *p2, size_t size)
{
	char buffer[size];

	memcpy(buffer, p1, size);
	memcpy(p1, p2, size);
	memcpy(p2, buffer, size);
}

static void
__qsort_with_data(void *base, size_t nelem, unsigned long *map,
		  struct qsort_context *ctx)
{
	void *p, *start, *end, *pivot;
	unsigned long *mp, *mstart, *mend, tmp;
	int left, right, result;
	size_t size = ctx->size;

	p = base;
	start = base;
	end = base + nelem * size;
	mp = map;
	mstart = map;
	mend = map + nelem;
	pivot = base + (random() % nelem) * size;

	while (p < end) {
		result = ctx->compare(p, pivot, ctx->data);
		if (result < 0) {
			qsort_swap(p, start, size);
			tmp = *mp;
			*mp = *mstart;
			*mstart = tmp;
			if (start == pivot)
				pivot = p;
			start += size;
			mstart++;
			p += size;
			mp++;
		} else if (result == 0) {
			p += size;
			mp++;
		} else {
 			end -= size;
			mend--;
			qsort_swap(p, end, size);
			tmp = *mp;
			*mp = *mend;
			*mend = tmp;
			if (end == pivot)
				pivot = p;
		}
	}

	left = (start - base) / size;
	right = (base + nelem * size - end) / size;
	if (left > 1)
		__qsort_with_data(base, left, map, ctx);
	if (right > 1)
		__qsort_with_data(end, right, mend, ctx);
}

unsigned long *
qsort_with_data(void *base, size_t nelem, size_t size,
		compare_with_data_func_t compare, void *data)
{
	struct qsort_context ctx;
	unsigned long *map;
	int i;

	ctx.size = size;
	ctx.compare = compare;
	ctx.data = data;

	map = malloc(nelem * sizeof (unsigned long));
	for (i = 0; i < nelem; i++)
		map[i] = i;

	__qsort_with_data(base, nelem, map, &ctx);

	return map;
}

static int
versioncmp(const char *s1, const char *s2)
{
	const char *p1, *p2;
	long n1, n2;
	int res;

	n1 = strtol(s1, (char **) &p1, 0);
	n2 = strtol(s2, (char **) &p2, 0);

	/* Epoch; if one but not the other has an epoch set, default
	 * the epoch-less version to 0. */
	res = (*p1 == ':') - (*p2 == ':');
	if (res < 0) {
		n1 = 0;
		p1 = s1;
		p2++;
	} else if (res > 0) {
		p1++;
		n2 = 0;
		p2 = s2;
	}

	if (n1 != n2)
		return n1 - n2;
	while (*p1 && *p2) {
		if (*p1 != *p2)
			return *p1 - *p2;
		p1++;
		p2++;
		if (isdigit(*p1) && isdigit(*p2))
			return versioncmp(p1, p2);
	}

	return *p1 - *p2;
}


static int
compare_packages(const void *p1, const void *p2, void *data)
{
	const struct razor_package *pkg1 = p1, *pkg2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	if (pkg1->name == pkg2->name)
		return versioncmp(&pool[pkg1->version], &pool[pkg2->version]);
	else
		return strcmp(&pool[pkg1->name], &pool[pkg2->name]);
}

static int
compare_properties(const void *p1, const void *p2, void *data)
{
	const struct razor_property *prop1 = p1, *prop2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	if (prop1->name == prop2->name)
		return versioncmp(&pool[prop1->version], &pool[prop2->version]);
	else
		return strcmp(&pool[prop1->name], &pool[prop2->name]);
}

static unsigned long *
uniqueify_properties(struct razor_set *set, struct array *properties)
{
	struct razor_property *rp, *up, *rp_end;
	struct array *pkgs, *p;
	unsigned long *map, *rmap, *r;
	int i, count, unique;

	count = properties->size / sizeof(struct razor_property);
	map = qsort_with_data(properties->data,
			      count,
			      sizeof(struct razor_property),
			      compare_properties,
			      set);

	rp_end = properties->data + properties->size;
	rmap = malloc(count * sizeof *map);
	pkgs = zalloc(count * sizeof *pkgs);
	for (rp = properties->data, up = rp, i = 0; rp < rp_end; rp++, i++) {
		if (rp->name != up->name || rp->version != up->version) {
			up++;
			up->name = rp->name;
			up->version = rp->version;
		}

		unique = up - (struct razor_property *) properties->data;
		rmap[map[i]] = unique;
		r = array_add(&pkgs[unique], sizeof *r);
		*r = rp->packages;
	}
	free(map);

	up++;
	properties->size = (void *) up - properties->data;
	rp_end = up;
	for (rp = properties->data, p = pkgs; rp < rp_end; rp++, p++) {
		if (p->size / sizeof *r == 1) {
			r = p->data;
			rp->packages = *r | RAZOR_IMMEDIATE;
		} else {
			rp->packages =
				add_to_property_pool(&set->package_pool, p);
		}
		array_release(p);
	}

	free(pkgs);

	return rmap;
}

static void
remap_links(struct array *links, unsigned long *map)
{
	unsigned long *p, *end;

	end = links->data + links->size;
	for (p = links->data; p < end; p++)
		if (*p != ~0)
			*p = map[*p];
}

static int
compare_filenames(const void *p1, const void *p2, void *data)
{
	const struct import_entry *e1 = p1;
	const struct import_entry *e2 = p2;

	return strcmp(e1->name, e2->name);
}

static void
count_entries(struct import_directory *d)
{
	struct import_directory *p, *end;

	p = d->files.data;
	end = d->files.data + d->files.size;
	d->count = 0;
	while (p < end) {
		count_entries(p);
		d->count += p->count + 1;
		p++;
	}		
}

static void
serialize_files(struct razor_set *set,
		struct import_directory *d, struct array *array)
{
	struct import_directory *p, *end;
	struct razor_entry *e = NULL;
	unsigned long s, *r;

	p = d->files.data;
	end = d->files.data + d->files.size;
	s = array->size / sizeof *e + d->files.size / sizeof *p;
	while (p < end) {
		e = array_add(array, sizeof *e);
		e->name = p->name;
		e->start = p->count > 0 ? s : 0;
		s += p->count;

		if (p->packages.size / sizeof *r == 1) {
			r = p->packages.data;
			e->packages = *r | RAZOR_IMMEDIATE;
		} else {
			e->packages = add_to_property_pool(&set->package_pool,
							   &p->packages);
		}
		array_release(&p->packages);
		p++;
	}		
	if (e != NULL)
		e->name |= RAZOR_ENTRY_LAST;

	p = d->files.data;
	end = d->files.data + d->files.size;
	while (p < end) {
		serialize_files(set, p, array);
		p++;
	}
}

static void
remap_property_package_links(struct array *properties, unsigned long *rmap)
{
	struct razor_property *p, *end;

	end = properties->data + properties->size;
	for (p = properties->data; p < end; p++)
		if (p->packages & RAZOR_IMMEDIATE)
			p->packages = rmap[p->packages & RAZOR_ENTRY_MASK] |
				RAZOR_IMMEDIATE;
}

static void
build_file_tree(struct razor_importer *importer)
{
	int count, i, length;
	struct import_entry *filenames;
	char *f, *end;
	unsigned long name, *r;
	char dirname[256];
	struct import_directory *d, root;
	struct razor_entry *e;

	count = importer->files.size / sizeof (struct import_entry);
	qsort_with_data(importer->files.data,
			count,
			sizeof (struct import_entry),
			compare_filenames,
			NULL);

	root.name = razor_importer_tokenize(importer, "");
	array_init(&root.files);
	array_init(&root.packages);
	root.last = NULL;

	filenames = importer->files.data;
	for (i = 0; i < count; i++) {
		f = filenames[i].name;
		if (*f != '/')
			continue;
		f++;

		d = &root;
		while (*f) {
			end = strchr(f, '/');
			if (end == NULL)
				end = f + strlen(f);
			length = end - f;
			memcpy(dirname, f, length);
			dirname[length] ='\0';
			name = razor_importer_tokenize(importer, dirname);
			if (d->last == NULL || d->last->name != name) {
				d->last = array_add(&d->files, sizeof *d);
				d->last->name = name;
				d->last->last = NULL;
				array_init(&d->last->files);
				array_init(&d->last->packages);
			}
			d = d->last;				
			f = end + 1;
			if (*end == '\0')
				break;
		}

		r = array_add(&d->packages, sizeof *r);
		*r = filenames[i].package;
		free(filenames[i].name);
	}

	count_entries(&root);
	array_init(&importer->set->files);

	e = array_add(&importer->set->files, sizeof *e);
	e->name = root.name | RAZOR_ENTRY_LAST;
	e->start = 1;
	e->packages = 0;

	serialize_files(importer->set, &root, &importer->set->files);

	array_release(&importer->files);
}

static void
build_package_file_lists(struct razor_set *set, unsigned long *rmap)
{
	struct razor_package *p, *packages;
	struct array *pkgs;
	struct razor_entry *e, *end;
	unsigned long *r, *q;
	int i, count;

	count = set->packages.size / sizeof *p;
	pkgs = zalloc(count * sizeof *pkgs);

	e = set->files.data;
	end = set->files.data + set->files.size;
	while (e < end) {
		if (e->packages & RAZOR_IMMEDIATE) {
			e->packages = rmap[e->packages & RAZOR_ENTRY_MASK] |
				RAZOR_IMMEDIATE;
			r = &e->packages;
		} else {
			r = (unsigned long *) set->package_pool.data + e->packages;
		}

		while (~*r) {
			q = array_add(&pkgs[*r & RAZOR_ENTRY_MASK], sizeof *q);
			*q = e - (struct razor_entry *) set->files.data;
			if (*r++ & RAZOR_IMMEDIATE)
				break;
		}
		e++;
	}

	packages = set->packages.data;
	for (i = 0; i < count; i++) {
		packages[i].files =
			add_to_property_pool(&set->file_pool, &pkgs[i]);
		array_release(&pkgs[i]);
	}
	free(pkgs);
}

struct razor_set *
razor_importer_finish(struct razor_importer *importer)
{
	struct razor_set *set;
	unsigned long *map, *rmap;
	int i, count;

	map = uniqueify_properties(importer->set, &importer->set->requires);
	remap_links(&importer->set->requires_pool, map);
	free(map);

	map = uniqueify_properties(importer->set, &importer->set->provides);
	remap_links(&importer->set->provides_pool, map);
	free(map);

	count = importer->set->packages.size / sizeof(struct razor_package);
	map = qsort_with_data(importer->set->packages.data,
			      count,
			      sizeof(struct razor_package),
			      compare_packages,
			      importer->set);

	rmap = malloc(count * sizeof *rmap);
	for (i = 0; i < count; i++)
		rmap[map[i]] = i;
	free(map);

	build_file_tree(importer);
	remap_links(&importer->set->package_pool, rmap);
	build_package_file_lists(importer->set, rmap);
	remap_property_package_links(&importer->set->requires, rmap);
	remap_property_package_links(&importer->set->provides, rmap);
	free(rmap);

	set = importer->set;
	array_release(&importer->buckets);
	free(importer);

	return set;
}

void
razor_set_list(struct razor_set *set, const char *pattern)
{
	struct razor_package *p, *end;
	int with_version = 0;
	char *pool;

	pool = set->string_pool.data;
	end = set->packages.data + set->packages.size;
	for (p = set->packages.data; p < end; p++) {
		if (pattern && fnmatch(pattern, &pool[p->name], 0) != 0)
		    continue;
		if (with_version)
			printf("%s-%s\n", &pool[p->name], &pool[p->version]);
		else
			printf("%s\n", &pool[p->name]);
	}
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
		printf("%s-%s\n", &pool[p->name], &pool[p->version]);
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
		r = (unsigned long *) set->requires_pool.data +
			package->requires;
		requires = set->requires.data;
		pool = set->string_pool.data;
		while (~*r) {
			p = &requires[*r++];
			printf("%s-%s\n", &pool[p->name], &pool[p->version]);
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
		r = (unsigned long *) set->provides_pool.data +
			package->provides;
		provides = set->provides.data;
		pool = set->string_pool.data;
		while (~*r) {
			p = &provides[*r++];
			printf("%s-%s\n", &pool[p->name], &pool[p->version]);
		}
	} else 
		razor_set_list_all_properties(set, &set->provides);
}

static void
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
		if (version && versioncmp(version, &pool[property->version]) != 0)
			goto next;
		
		if (property->packages & RAZOR_IMMEDIATE)
			r = &property->packages;
		else
			r = (unsigned long *)
				set->package_pool.data + property->packages;
		while (~*r) {
			p = &packages[*r & RAZOR_ENTRY_MASK];
			printf("%s-%s\n", &pool[p->name], &pool[p->version]);
			if (*r++ & RAZOR_IMMEDIATE)
				break;
		}
	next:
		property++;
	}
}

void
razor_set_list_requires_packages(struct razor_set *set,
				 const char *name,
				 const char *version)
{
	razor_set_list_property_packages(set, &set->requires, name, version);
}

void
razor_set_list_provides_packages(struct razor_set *set,
				 const char *name,
				 const char *version)
{
	razor_set_list_property_packages(set, &set->provides, name, version);
}

static struct razor_entry *
find_entry(struct razor_set *set, struct razor_entry *dir, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->string_pool.data;
	int len;

	e = (struct razor_entry *) set->files.data + dir->start;
	do {
		n = pool + (e->name & RAZOR_ENTRY_MASK);
		if (strcmp(pattern + 1, n) == 0)
			return e;
		len = strlen(n);
		if (e->start != 0 && strncmp(pattern + 1, n, len) == 0 &&
		    pattern[len + 1] == '/') {
			return find_entry(set, e, pattern + len + 1);
		}
	} while (((e++)->name & RAZOR_ENTRY_LAST) == 0);

	return NULL;
}

static void
list_dir(struct razor_set *set, struct razor_entry *dir,
	 const char *prefix, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->string_pool.data;

	e = (struct razor_entry *) set->files.data + dir->start;
	do {
		n = pool + (e->name & RAZOR_ENTRY_MASK);
		if (pattern && pattern[0] && fnmatch(pattern, n, 0) != 0)
			continue;
		printf("%s/%s%s\n", prefix, n, e->start > 0 ? "/" : "");
	} while (((e++)->name & RAZOR_ENTRY_LAST) == 0);
}

void
razor_set_list_files(struct razor_set *set, const char *pattern)
{
	struct razor_entry *e;
	char buffer[512], *p, *base;

	if (pattern == NULL)
		pattern = "/";

	strcpy(buffer, pattern);
	e = find_entry(set, set->files.data, buffer);
	if (e && e->start > 0) {
		base = NULL;
	} else {
		p = strrchr(buffer, '/');
		if (p) {
			*p = '\0';
			base = p + 1;
		} else {
			base = NULL;
		}
	}
	e = find_entry(set, set->files.data, buffer);
	if (e->start != 0)
		list_dir(set, e, buffer, base);
}

void
razor_set_list_file_packages(struct razor_set *set, const char *filename)
{
	struct razor_entry *e;
	struct razor_package *packages, *p;
	const char *pool;
	unsigned long *r;

	e = find_entry(set, set->files.data, filename);
	if (e == NULL)
		return;
	
	if (e->packages & RAZOR_IMMEDIATE)
		r = &e->packages;
	else
		r = (unsigned long *) set->package_pool.data + e->packages;

	packages = set->packages.data;
	pool = set->string_pool.data;
	while (~*r) {
		p = &packages[*r & RAZOR_ENTRY_MASK];
		printf("%s-%s\n", &pool[p->name], &pool[p->version]);
		if (*r++ & RAZOR_IMMEDIATE)
			break;
	}
}

static unsigned long *
list_package_files(struct razor_set *set, unsigned long *r,
		   struct razor_entry *dir, unsigned long end,
		   char *prefix)
{
	struct razor_entry *e, *f, *entries;
	unsigned long next;
	char *pool;
	int len;
	
	entries = (struct razor_entry *) set->files.data;
	pool = set->string_pool.data;

	e = entries + dir->start;
	do {
		if (entries + *r == e) {
			printf("%s/%s\n", prefix,
			       pool + (e->name & RAZOR_ENTRY_MASK));
			r++;
			if (*r >= end)
				break;
		}
	} while (((e++)->name & RAZOR_ENTRY_LAST) == 0);

	e = entries + dir->start;
	do {
		if (e->start == 0)
			continue;

		if (e->name & RAZOR_ENTRY_LAST)
			next = end;
		else {
			f = e + 1; 
			while (f->start == 0 && !(f->name & RAZOR_ENTRY_LAST))
				f++;
			if (f->start == 0)
				next = end;
			else
				next = f->start;
		}

		if (e->start <= *r && *r < next) {
			len = strlen(prefix);
			prefix[len] = '/';
			strcpy(prefix + len + 1,
			       pool + (e->name & RAZOR_ENTRY_MASK));
			r = list_package_files(set, r, e, next, prefix);
			prefix[len] = '\0';
			if (*r >= end)
				break;
		}
	} while (((e++)->name & RAZOR_ENTRY_LAST) == 0);

	return r;
}

void
razor_set_list_package_files(struct razor_set *set, const char *name)
{
	struct razor_package *package;
	unsigned long *r, end;
	char buffer[512];

	package = razor_set_get_package(set, name);

	r = (unsigned long *) set->file_pool.data + package->files;
	end = set->files.size / sizeof (struct razor_entry);
	buffer[0] = '\0';
	list_package_files(set, r, set->files.data, end, buffer);
}

static void
razor_set_validate(struct razor_set *set, struct array *unsatisfied)
{
	struct razor_property *r, *p, *rend, *pend;
	unsigned long *u;
	char *pool;

	p = set->provides.data;
	rend = set->requires.data + set->requires.size;
	pend = set->provides.data + set->provides.size;
	pool = set->string_pool.data;
	
	for (r = set->requires.data; r < rend; r++) {
		while (p < pend && strcmp(&pool[r->name], &pool[p->name]) > 0)
			p++;

		/* If there is more than one version of a provides,
		 * seek to the end for the highest version. */
		while (p + 1 < pend && p->name == (p + 1)->name)
			p++;

		/* FIXME: We need to track property flags (<, <=, =
		 * etc) to properly determine if a requires is
		 * satisfied.  The current code doesn't track that the
		 * requires a = 1 isn't satisfied by a = 2 provides. */

		if (p == pend || strcmp(&pool[r->name], &pool[p->name]) != 0 ||
		    versioncmp(&pool[r->version], &pool[p->version]) > 0) {
			/* FIXME: We ignore file requires for now. */
			if (pool[r->name] == '/')
				continue;
			u = array_add(unsatisfied, sizeof *u);
			*u = r - (struct razor_property *) set->requires.data;
		}
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
		printf("%s-%s not satisfied\n",
		       &pool[r->name], &pool[r->version]);
	}

	array_release(&unsatisfied);
}

#define UPSTREAM_SOURCE 0x80000000ul
#define INDEX_MASK 0x00fffffful

struct source {
	struct razor_set *set;
	unsigned long *requires_map;
	unsigned long *provides_map;
};

static void
prepare_source(struct source *source, struct razor_set *set)
{
	int count;
	size_t size;

	source->set = set;

	count = set->requires.size / sizeof (struct razor_property);
	size = count * sizeof *source->requires_map;
	source->requires_map = zalloc(size);

	count = set->provides.size / sizeof (struct razor_property);
	size = count * sizeof *source->provides_map;
	source->provides_map = zalloc(size);
}

static void
add_package(struct razor_importer *importer,
	    struct razor_package *package, struct source *source,
	    unsigned long flags)
{
	char *pool;
	unsigned long *r;
	struct razor_package *p;

	pool = source->set->string_pool.data;
	p = array_add(&importer->set->packages, sizeof *p);
	p->name = razor_importer_tokenize(importer, &pool[package->name]);
	p->name |= flags;
	p->version = razor_importer_tokenize(importer,
					     &pool[package->version]);
	p->requires = package->requires;
	p->provides = package->provides;

	r = (unsigned long *)
		source->set->requires_pool.data + package->requires;
	while (*r != ~0)
		source->requires_map[*r++] = 1;

	r = (unsigned long *)
		source->set->provides_pool.data + package->provides;
	while (*r != ~0)
		source->provides_map[*r++] = 1;
}


/* Build the new package list sorted by merging the two package lists.
 * Build new string pool as we go. (for now we just re-use that part of
 * the importer). */
static void
merge_packages(struct razor_importer *importer,
	       struct source *source1, struct source *source2,
	       struct array *packages)
{
	struct razor_package *upstream_packages, *p, *s, *send;
	char *spool, *upool;
	unsigned long *u, *uend;
	int cmp;

	upstream_packages = source2->set->packages.data;

	u = packages->data;
	uend = packages->data + packages->size;
	upool = source2->set->string_pool.data;

	s = source1->set->packages.data;
	send = source1->set->packages.data + source1->set->packages.size;
	spool = source1->set->string_pool.data;

	while (s < send) {
		p = upstream_packages + *u;

		if (u < uend)
			cmp = strcmp(&spool[s->name], &upool[p->name]);
		if (u >= uend || cmp < 0) {
			add_package(importer, s, source1, 0);
			s++;
		} else if (cmp == 0) {
			add_package(importer, p, source2, UPSTREAM_SOURCE);
			s++;
			u++;
		} else {
			add_package(importer, p, source2, UPSTREAM_SOURCE);
			u++;
		}
	}
}

static unsigned long
add_property(struct razor_importer *importer, struct array *properties,
	     const char *name, const char *version)
{
	struct razor_property *p;

	p = array_add(properties, sizeof *p);
	p->name = razor_importer_tokenize(importer, name);
	p->version = razor_importer_tokenize(importer, version);

	return p - (struct razor_property *) properties->data;
}

static void
merge_properties(struct array *properties,
		 struct razor_importer *importer,
		 struct razor_set *set1,
		 struct array *properties1,
		 unsigned long *map1,
		 struct razor_set *set2,
		 struct array *properties2,
		 unsigned long *map2)
{
	struct razor_property *p1, *p2;
	int i, j, cmp, count1, count2;
	char *pool1, *pool2;

	i = 0;
	j = 0;
	pool1 = set1->string_pool.data;
	pool2 = set2->string_pool.data;

	count1 = properties1->size / sizeof *p1;
	count2 = properties2->size / sizeof *p2;
	while (i < count1 || j < count2) {
		if (i < count1 && map1[i] == 0) {
			i++;
			continue;
		}
		if (j < count2 && map2[j] == 0) {
			j++;
			continue;
		}
		p1 = (struct razor_property *) properties1->data + i;
		p2 = (struct razor_property *) properties2->data + j;
		if (i < count1 && j < count2)
			cmp = strcmp(&pool1[p1->name], &pool2[p2->name]);
		else if (i < count1)
			cmp = -1;
		else
			cmp = 1;
		if (cmp == 0)
			cmp = versioncmp(&pool1[p1->version],
					 &pool2[p2->version]);
		if (cmp < 0) {
			map1[i++] = add_property(importer,
						 properties,
						 &pool1[p1->name],
						 &pool1[p1->version]);
		} else if (cmp > 0) {
			map2[j++] = add_property(importer,
						 properties,
						 &pool2[p2->name],
						 &pool2[p2->version]);
		} else  {
			map1[i++] = map2[j++] = add_property(importer,
							     properties,
							     &pool1[p1->name],
							     &pool1[p1->version]);
		}
	}
}

static unsigned long
emit_properties(struct array *source_pool, unsigned long index,
		unsigned long *map, struct array *pool)
{
	unsigned long r, *p, *q;

	r = pool->size / sizeof *q;
	p = (unsigned long *) source_pool->data + index;
	while (*p != ~0) {
		q = array_add(pool, sizeof *q);
		*q = map[*p++];
	}

	q = array_add(pool, sizeof *q);
	*q = ~0;

	return r;
}
	
/* Rebuild property->packages maps.  We can't just remap these, as a
 * property may have lost or gained a number of packages.  Allocate an
 * array per property and loop through the packages and add them to
 * the arrays for their properties. */
static void
rebuild_package_lists(struct razor_set *set)
{
	int requires_count, provides_count;
	struct array *requires_pkgs, *provides_pkgs, *a;
	struct razor_package *pkg, *pkg_end;
	struct razor_property *prop, *prop_end;
	unsigned long *r, *q, *rpool, *ppool;

	requires_count = set->requires.size / sizeof (struct razor_property);
	provides_count = set->provides.size / sizeof (struct razor_property);
	requires_pkgs = zalloc(requires_count * sizeof *requires_pkgs);
	provides_pkgs = zalloc(provides_count * sizeof *provides_pkgs);
	pkg_end = set->packages.data + set->packages.size;
	rpool = set->requires_pool.data;
	ppool = set->provides_pool.data;

	for (pkg = set->packages.data; pkg < pkg_end; pkg++) {
		for (r = &rpool[pkg->requires]; *r != ~0; r++) {
			q = array_add(&requires_pkgs[*r], sizeof *q);
			*q = pkg - (struct razor_package *) set->packages.data;
		}
		for (r = &ppool[pkg->provides]; *r != ~0; r++) {
			q = array_add(&provides_pkgs[*r], sizeof *q);
			*q = pkg - (struct razor_package *) set->packages.data;
		}
	}

	prop_end = set->requires.data + set->requires.size;
	a = requires_pkgs;
	for (prop = set->requires.data; prop < prop_end; prop++, a++) {
		if (a->size / sizeof *r == 1) {
			r = a->data;
			prop->packages = *r | RAZOR_IMMEDIATE;
		} else {
			prop->packages =
				add_to_property_pool(&set->requires_pool, a);
		}
		array_release(a);
	}
	free(requires_pkgs);

	prop_end = set->provides.data + set->provides.size;
	a = provides_pkgs;
	for (prop = set->provides.data; prop < prop_end; prop++, a++) {
		if (a->size / sizeof *r == 1) {
			r = a->data;
			prop->packages = *r | RAZOR_IMMEDIATE;
		} else {
			prop->packages =
				add_to_property_pool(&set->provides_pool, a);
		}
		array_release(a);
	}
	free(provides_pkgs);
}

/* Add packages from 'upstream' to 'set'.  The packages to add are
 * specified by the 'packages' array, which is a sorted list of
 * package indexes.  Returns a newly allocated package set.  Does not
 * enforce validity of the resulting package set.
 *
 * This looks more complicated than it is.  An easy way to merge two
 * package sets would be to just use a razor_importer, but that
 * requires resorting, and is thus O(n log n).  We can do this in a
 * linear sweep, but it gets a little more complicated.
 */
struct razor_set *
razor_set_add(struct razor_set *set, struct razor_set *upstream,
	      struct array *packages)
{
	struct razor_set *result;
	struct razor_importer *importer;
	struct razor_package *p, *pend;
	struct source source, upstream_source;

	importer = razor_importer_new();

	prepare_source(&upstream_source, upstream);
	prepare_source(&source, set);

	merge_packages(importer, &source, &upstream_source, packages);

	/* As we built the package list, we filled out a bitvector of
	 * the properties that are referenced by the packages in the
	 * new set.  Now we do a parallel loop through the properties
	 * and emit those marked in the bit vector to the new set.  In
	 * the process, we update the bit vector to actually map from
	 * indices in the old property list to indices in the new
	 * property list for both sets. */

	merge_properties(&importer->set->requires, importer,
			 set, &set->requires, source.requires_map,
			 upstream, &upstream->requires,
			 upstream_source.requires_map);
	merge_properties(&importer->set->provides, importer,
			 set, &set->provides, source.provides_map,
			 upstream, &upstream->provides,
			 upstream_source.provides_map);

	/* Now we loop through the packages again and emit the
	 * property lists, remapped to point to the new properties. */

	pend = importer->set->packages.data + importer->set->packages.size;
	for (p = importer->set->packages.data; p < pend; p++) {
		struct source *src;

		if (p->name & UPSTREAM_SOURCE)
			src = &upstream_source;
		else
			src = &source;

		p->requires = emit_properties(&src->set->requires_pool,
					      p->requires,
					      src->requires_map,
					      &importer->set->requires_pool);
		p->provides = emit_properties(&src->set->provides_pool,
					      p->provides,
					      src->provides_map,
					      &importer->set->provides_pool);
		p->name &= INDEX_MASK;
	}

	rebuild_package_lists(importer->set);

	result = importer->set;
	array_release(&importer->buckets);
	free(importer);

	return result;
}

void
razor_set_satisfy(struct razor_set *set, struct array *unsatisfied,
		  struct razor_set *upstream, struct array *list)
{
	struct razor_property *requires, *r;
	struct razor_property *p, *pend;
	unsigned long *u, *end, *pkg, *package_pool;
	char *pool, *upool;

	end = unsatisfied->data + unsatisfied->size;
	requires = set->requires.data;
	pool = set->string_pool.data;

	p = upstream->provides.data;
	pend = upstream->provides.data + upstream->provides.size;
	upool = upstream->string_pool.data;
	package_pool = upstream->package_pool.data;

	for (u = unsatisfied->data; u < end; u++) {
		r = requires + *u;

		while (p < pend && strcmp(&pool[r->name], &upool[p->name]) > 0)
			p++;
		/* If there is more than one version of a provides,
		 * seek to the end for the highest version. */
		while (p + 1 < pend && p->name == (p + 1)->name)
			p++;

		if (p == pend ||
		    strcmp(&pool[r->name], &upool[p->name]) != 0 ||
		    versioncmp(&pool[r->version], &upool[p->version]) > 0) {
			/* Do we need to track unsatisfiable requires
			 * as we go, or should we just do a
			 * razor_set_validate() at the end? */
		} else {
			pkg = array_add(list, sizeof *pkg);
			/* We just pull in the first package that provides */
			if (p->packages & RAZOR_IMMEDIATE)
				*pkg = p->packages & RAZOR_ENTRY_MASK;
			else
				*pkg = package_pool[p->packages];
		}
	}	
}

static void
find_packages(struct razor_set *set,
	      int count, const char **packages, struct array *list)
{
	struct razor_package *p;
	unsigned long *r;
	int i;

	/* FIXME: Sort the packages. */
	for (i = 0; i < count; i++) {
		p = razor_set_get_package(set, packages[i]);
		r = array_add(list, sizeof *r);
		*r = p - (struct razor_package *) set->packages.data;
	}
}

static void
find_all_packages(struct razor_set *set,
		  struct razor_set *upstream, struct array *list)
{
	struct razor_package *p, *u, *pend, *uend;
	unsigned long *r;
	char *pool, *upool;

	pend = set->packages.data + set->packages.size;
	pool = set->string_pool.data;
	u = upstream->packages.data;
	uend = upstream->packages.data + upstream->packages.size;
	upool = upstream->string_pool.data;

	for (p = set->packages.data; p < pend; p++) {
		while (u < uend && strcmp(&pool[p->name], &upool[u->name]) > 0)
			u++;
		if (strcmp(&pool[p->name], &upool[u->name]) == 0) {
			r = array_add(list, sizeof *r);
			*r = u - (struct razor_package *) upstream->packages.data;
		}
	}
}

struct razor_set *
razor_set_update(struct razor_set *set, struct razor_set *upstream,
		 int count, const char **packages)
{
	struct razor_set *new;
	struct razor_package *upackages;
	struct array list, unsatisfied;
	char *pool;
	unsigned long *u, *end;
	int total = 0;

	array_init(&list);
	if (count > 0)
		find_packages(upstream, count, packages, &list);
	else
		find_all_packages(set, upstream, &list);

	end = list.data + list.size;
	upackages = upstream->packages.data;
	pool = upstream->string_pool.data;
	total += list.size / sizeof *u;

	while (list.size > 0) {
		new = razor_set_add(set, upstream, &list);
		array_release(&list);
		razor_set_destroy(set);
		set = new;

		array_init(&unsatisfied);
		razor_set_validate(new, &unsatisfied);
		array_init(&list);
		razor_set_satisfy(new, &unsatisfied, upstream, &list);
		array_release(&unsatisfied);

		end = list.data + list.size;
		upackages = upstream->packages.data;
		pool = upstream->string_pool.data;
		total += list.size / sizeof *u;
	}

	array_release(&list);

	return set;
}

/* The diff order matters.  We should sort the packages so that a
 * REMOVE of a package comes before the INSTALL, and so that all
 * requires for a package have been installed before the package.
 **/

void
razor_set_diff(struct razor_set *set, struct razor_set *upstream,
	       razor_package_callback_t callback, void *data)
{
	struct razor_package *p, *pend, *u, *uend;
	char *ppool, *upool;
	int res = 0;

	p = set->packages.data;
	pend = set->packages.data + set->packages.size;
	ppool = set->string_pool.data;

	u = upstream->packages.data;
	uend = upstream->packages.data + upstream->packages.size;
	upool = upstream->string_pool.data;

	while (p < pend || u < uend) {
		if (p < pend && u < uend) {
			res = strcmp(&ppool[p->name], &upool[u->name]);
			if (res == 0)
				res = versioncmp(&ppool[p->version],
						 &upool[u->version]);
		}

		if (u == uend || res < 0) {
			callback(&ppool[p->name], &ppool[p->version],
				 NULL, data);
			p++;
			continue;
		} else if (p == pend || res > 0) {
			callback(&upool[u->name], NULL, &upool[u->version],
				 data);
			u++;
			continue;
		} else {
			p++;
			u++;
		}
	}
}
