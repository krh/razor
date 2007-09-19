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

#include "razor.h"

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

struct razor_importer {
	struct razor_set *set;
	struct array buckets;
	struct import_property_context requires;
	struct import_property_context provides;
	struct razor_package *package;
	unsigned long *requires_map;
	unsigned long *provides_map;
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
	} else {
		for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
			a = (void *) set + razor_sections[i].offset;
			free(a->data);
		}
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
	p->requires = add_to_property_pool(importer->set,
					   &importer->requires.package);
	p->provides = add_to_property_pool(importer->set,
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
compare_packages(const void *p1, const void *p2, void *data)
{
	const struct razor_package *pkg1 = p1, *pkg2 = p2;
	struct razor_set *set = data;
	char *pool = set->string_pool.data;

	if (pkg1->name == pkg2->name)
		return strcmp(&pool[pkg1->version], &pool[pkg2->version]);
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
		return strcmp(&pool[prop1->version], &pool[prop2->version]);
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
		rp->packages = add_to_property_pool(set, p);
		array_release(p);
	}

	free(pkgs);

	return rmap;
}

static void
remap_package_links(struct razor_importer *importer)
{
	struct razor_package *p, *end;
	unsigned long *pool, *r;

	pool = importer->set->property_pool.data;
	end = importer->set->packages.data + importer->set->packages.size;
	for (p = importer->set->packages.data; p < end; p++) {
		for (r = &pool[p->requires]; ~*r; r++)
			*r = importer->requires_map[*r];
		for (r = &pool[p->provides]; ~*r; r++)
			*r = importer->provides_map[*r];
	}
}

static void
remap_property_links(struct razor_importer *importer, unsigned long *map)
{
	struct razor_property *p, *end;
	struct razor_package *rp;
	unsigned long *pool, *r, *rmap;
	int i, count;

	pool = importer->set->property_pool.data;
	count = importer->set->packages.size / sizeof(struct razor_package);
	rmap = malloc(count * sizeof *map);
	rp = importer->set->packages.data;
	for (i = 0; i < count; i++)
		rmap[map[i]] = i;

	/* FIXME: This will break if we implement package list sharing
	 * for all properties, since we'll remap those lists more than
	 * once. We should just have a separate pool for property
	 * lists and a separate pool for package lists and remap it as
	 * a flat pool.  Right now, as property lists and package
	 * lists are mixed, we can't do that. */

	end = importer->set->requires.data + importer->set->requires.size;
	for (p = importer->set->requires.data; p < end; p++)
		for (r = &pool[p->packages]; ~*r; r++)
			*r = rmap[*r];

	end = importer->set->provides.data + importer->set->provides.size;
	for (p = importer->set->provides.data; p < end; p++)
		for (r = &pool[p->packages]; ~*r; r++)
			*r = rmap[*r];

	free(rmap);
}

struct razor_set *
razor_importer_finish(struct razor_importer *importer)
{
	struct razor_set *set;
	unsigned long *map;
	int count;

	importer->requires_map = uniqueify_properties(importer->set,
						      importer->requires.all);
	importer->provides_map = uniqueify_properties(importer->set,
						      importer->provides.all);
	remap_package_links(importer);
	free(importer->requires_map);
	free(importer->provides_map);

	count = importer->set->packages.size / sizeof(struct razor_package);
	map = qsort_with_data(importer->set->packages.data,
			      count,
			      sizeof(struct razor_package),
			      compare_packages,
			      importer->set);
	remap_property_links(importer, map);
	free(map);

	set = importer->set;
	array_release(&importer->buckets);
	free(importer);

	return set;
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

static void
add_package(struct razor_importer *importer,
	    struct razor_package *package, struct razor_set *set)
{
	char *pool;
	unsigned long *r;
	struct razor_property *p, *properties;

	pool = set->string_pool.data;
	razor_importer_begin_package(importer,
				     &pool[package->name],
				     &pool[package->version]);

	r = (unsigned long *) set->property_pool.data + package->requires;
	properties = set->requires.data;
	while (~*r) {
		p = &properties[*r++];
		razor_importer_add_requires(importer,
					    &pool[p->name], &pool[p->version]);
	}

	r = (unsigned long *) set->property_pool.data + package->provides;
	properties = set->provides.data;
	while (~*r) {
		p = &properties[*r++];
		razor_importer_add_provides(importer,
					    &pool[p->name], &pool[p->version]);
	}

	razor_importer_finish_package(importer);
}

/* Add packages from 'upstream' to 'set'.  The packages to add are
 * specified by the 'packages' array, which is a sorted list of
 * package indexes.  Returns a newly allocated package set.  Does not
 * enforce validity of the resulting package set. */

struct razor_set *
razor_set_add(struct razor_set *set, struct razor_set *upstream,
	      struct array *packages)
{
	struct razor_importer *importer;
	struct razor_package *upstream_packages, *p, *s, *send;
	char *spool, *upool;
	unsigned long *u, *uend;
	int cmp;

	importer = razor_importer_new();
	upstream_packages = upstream->packages.data;
	u = packages->data;
	uend = packages->data + packages->size;
	upool = upstream->string_pool.data;
	s = set->packages.data;
	send = set->packages.data + set->packages.size;
	spool = set->string_pool.data;

	while (s < send) {
		p = upstream_packages + *u;
		cmp = strcmp(&spool[s->name], &upool[p->name]);
		if (cmp < 0 || u == uend) {
			add_package(importer, s, set);
			s++;
		} else if (cmp == 0) {
			add_package(importer, p, upstream);
			s++;
			u++;
		} else {
			add_package(importer, p, upstream);
			u++;
		}
	}

	return razor_importer_finish(importer);
}

struct razor_set *
razor_set_update(struct razor_set *set, struct razor_set *upstream,
		 int count, const char **packages)
{
	struct razor_package *p;
	struct array list;
	unsigned long *r;
	int i;

	array_init(&list);
	for (i = 0; i < count; i++) {
		p = razor_set_get_package(upstream, packages[i]);
		r = array_add(&list, sizeof *r);
		*r = p - (struct razor_package *) upstream->packages.data;
	}

	return razor_set_add(set, upstream, &list);
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
main(int argc, const char *argv[])
{
	struct razor_set *set, *upstream, *new;
	struct stat statbuf;
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
			
		set = razor_import_rzr_files(argc - 2, argv + 2);

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
	} else if (strcmp(argv[1], "import-rpmdb") == 0) {
		set = razor_set_create_from_rpmdb();
		if (set == NULL)
			return 1;
		razor_set_write(set, repo_filename);
		razor_set_destroy(set);
		printf("wrote %s\n", repo_filename);
	} else if (strcmp(argv[1], "validate") == 0) {
		set = razor_set_open(repo_filename);
		if (set == NULL)
			return 1;
		razor_set_list_unsatisfied(set);
		razor_set_destroy(set);
	} else if (strcmp(argv[1], "update") == 0) {
		set = razor_set_open(repo_filename);
		upstream = razor_set_open(rawhide_repo_filename);
		if (set == NULL || upstream == NULL)
			return 1;
		new = razor_set_update(set, upstream, argc - 2, argv + 2);
		razor_set_write(new, "system-updated.repo");
		razor_set_destroy(new);
		razor_set_destroy(set);
		razor_set_destroy(upstream);
	} else {
		usage();
	}

	return 0;
}
