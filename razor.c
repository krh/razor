#define _GNU_SOURCE

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
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
#include "razor-internal.h"
#include "types.h"

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

#define RAZOR_MAGIC 0x7a7a7a7a
#define RAZOR_VERSION 1

#define RAZOR_STRING_POOL	0
#define RAZOR_PACKAGES		1
#define RAZOR_PROPERTIES	2
#define RAZOR_FILES		3
#define RAZOR_PACKAGE_POOL	4
#define RAZOR_PROPERTY_POOL	5
#define RAZOR_FILE_POOL		6

struct razor_package {
	uint name  : 24;
	uint flags : 8;
	uint32_t version;
	struct list_head properties;
	struct list_head files;
};

struct razor_property {
	uint name  : 24;
	uint flags : 6;
	uint type  : 2;
	uint32_t relation;
	uint32_t version;
	struct list_head packages;
};

struct razor_entry {
	uint name  : 24;
	uint flags : 8;
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
	struct razor_set_header *header;
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
	struct razor_package *package;
	struct array properties;
	struct array files;
};

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
	{ RAZOR_PROPERTIES,	offsetof(struct razor_set, properties) },
	{ RAZOR_FILES,		offsetof(struct razor_set, files) },
	{ RAZOR_PACKAGE_POOL,	offsetof(struct razor_set, package_pool) },
	{ RAZOR_PROPERTY_POOL,	offsetof(struct razor_set, property_pool) },
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
	uint32_t offset;
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
		offset += ALIGN(a->size, 4096);
	}

	header->sections[i].type = ~0;
	header->sections[i].offset = 0;
	header->sections[i].size = 0;

	fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0666);
	if (fd < 0)
		return -1;

	razor_write(fd, data, sizeof data);
	memset(data, 0, sizeof data);
	for (i = 0; i < ARRAY_SIZE(razor_sections); i++) {
		if (razor_sections[i].type != i)
			continue;
		a = (void *) set + razor_sections[i].offset;
		razor_write(fd, a->data, a->size);
		razor_write(fd, data, ALIGN(a->size, 4096) - a->size);
	}

	close(fd);

	return 0;
}

void
razor_importer_begin_package(struct razor_importer *importer,
			     const char *name, const char *version)
{
	struct razor_package *p;

	p = array_add(&importer->set->packages, sizeof *p);
	p->name = hashtable_tokenize(&importer->table, name);
	p->flags = 0;
	p->version = hashtable_tokenize(&importer->table, version);

	importer->package = p;
	array_init(&importer->properties);
}

void
razor_importer_finish_package(struct razor_importer *importer)
{
	list_set_array(&importer->package->properties,
		       &importer->set->property_pool,
		       &importer->properties);

	array_release(&importer->properties);
}

void
razor_importer_add_property(struct razor_importer *importer,
			    const char *name,
			    enum razor_version_relation relation,
			    const char *version,
			    enum razor_property_type type)
{
	struct razor_property *p;
	uint32_t *r;

	p = array_add(&importer->set->properties, sizeof *p);
	p->name = hashtable_tokenize(&importer->table, name);
	p->flags = 0;
	p->type = type;
	p->relation = relation;
	p->version = hashtable_tokenize(&importer->table, version);
	list_set_ptr(&p->packages, importer->package -
		     (struct razor_package *) importer->set->packages.data);

	r = array_add(&importer->properties, sizeof *r);
	*r = p - (struct razor_property *) importer->set->properties.data;
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
	hashtable_init(&importer->table, &importer->set->string_pool);

	return importer;
}

/* Destroy an importer without creating the set. */
void
razor_importer_destroy(struct razor_importer *importer)
{
	/* FIXME: write this */
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
__qsort_with_data(void *base, size_t nelem, uint32_t *map,
		  struct qsort_context *ctx)
{
	void *p, *start, *end, *pivot;
	uint32_t *mp, *mstart, *mend, tmp;
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

uint32_t *
qsort_with_data(void *base, size_t nelem, size_t size,
		compare_with_data_func_t compare, void *data)
{
	struct qsort_context ctx;
	uint32_t *map;
	int i;

	if (nelem == 0)
		return NULL;

	ctx.size = size;
	ctx.compare = compare;
	ctx.data = data;

	map = malloc(nelem * sizeof (uint32_t));
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

	/* FIXME: what if the flags are different? */
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

	if (prop1->name != prop2->name) 
		return strcmp(&pool[prop1->name], &pool[prop2->name]);
	else if (prop1->type != prop2->type)
		return prop1->type - prop2->type;
	else if (prop1->relation != prop2->relation)
		return prop1->relation - prop2->relation;
	else
		return versioncmp(&pool[prop1->version], &pool[prop2->version]);
}

static uint32_t *
uniqueify_properties(struct razor_set *set)
{
	struct razor_property *rp, *up, *rp_end;
	struct array *pkgs, *p;
	struct list_head *r;
	uint32_t *map, *rmap;
	int i, count, unique;

	count = set->properties.size / sizeof(struct razor_property);
	map = qsort_with_data(set->properties.data,
			      count,
			      sizeof(struct razor_property),
			      compare_properties,
			      set);

	rp_end = set->properties.data + set->properties.size;
	rmap = malloc(count * sizeof *map);
	pkgs = zalloc(count * sizeof *pkgs);
	for (rp = set->properties.data, up = rp, i = 0; rp < rp_end; rp++, i++) {
		if (rp->name != up->name || rp->type != up->type ||
		    rp->relation != up->relation || rp->version != up->version) {
			up++;
			up->name = rp->name;
			up->flags = 0;
			up->type = rp->type;
			up->relation = rp->relation;
			up->version = rp->version;
		}

		unique = up - (struct razor_property *) set->properties.data;
		rmap[map[i]] = unique;
		r = array_add(&pkgs[unique], sizeof *r);
		*r = rp->packages;
	}
	free(map);

	up++;
	set->properties.size = (void *) up - set->properties.data;
	rp_end = up;
	for (rp = set->properties.data, p = pkgs; rp < rp_end; rp++, p++) {
		list_set_array(&rp->packages, &set->package_pool, p);
		array_release(p);
	}

	free(pkgs);

	return rmap;
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
	uint32_t s;

	p = d->files.data;
	end = d->files.data + d->files.size;
	s = array->size / sizeof *e + d->files.size / sizeof *p;
	while (p < end) {
		e = array_add(array, sizeof *e);
		e->name = p->name;
		e->flags = 0;
		e->start = p->count > 0 ? s : 0;
		s += p->count;

		list_set_array(&e->packages, &set->package_pool, &p->packages);
		array_release(&p->packages);
		p++;
	}		
	if (e != NULL)
		e->flags |= RAZOR_ENTRY_LAST;

	p = d->files.data;
	end = d->files.data + d->files.size;
	while (p < end) {
		serialize_files(set, p, array);
		p++;
	}
}

static void
remap_property_package_links(struct array *properties, uint32_t *rmap)
{
	struct razor_property *p, *end;

	end = properties->data + properties->size;
	for (p = properties->data; p < end; p++)
		list_remap_head(&p->packages, rmap);
}

static void
build_file_tree(struct razor_importer *importer)
{
	int count, i, length;
	struct import_entry *filenames;
	char *f, *end;
	uint32_t name, *r;
	char dirname[256];
	struct import_directory *d, root;
	struct razor_entry *e;

	count = importer->files.size / sizeof (struct import_entry);
	qsort_with_data(importer->files.data,
			count,
			sizeof (struct import_entry),
			compare_filenames,
			NULL);

	root.name = hashtable_tokenize(&importer->table, "");
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
			name = hashtable_tokenize(&importer->table, dirname);
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
	e->name = root.name;
	e->flags = RAZOR_ENTRY_LAST;
	e->start = 1;
	list_set_empty(&e->packages);

	serialize_files(importer->set, &root, &importer->set->files);

	array_release(&importer->files);
}

static void
build_package_file_lists(struct razor_set *set, uint32_t *rmap)
{
	struct razor_package *p, *packages;
	struct array *pkgs;
	struct razor_entry *e, *end;
	struct list *r;
	uint32_t *q;
	int i, count;

	count = set->packages.size / sizeof *p;
	pkgs = zalloc(count * sizeof *pkgs);

	end = set->files.data + set->files.size;
	for (e = set->files.data; e < end; e++) {
		list_remap_head(&e->packages, rmap);
		r = list_first(&e->packages, &set->package_pool);
		while (r) {
			q = array_add(&pkgs[r->data], sizeof *q);
			*q = e - (struct razor_entry *) set->files.data;
			r = list_next(r);
		}
	}

	packages = set->packages.data;
	for (i = 0; i < count; i++) {
		list_set_array(&packages[i].files, &set->file_pool, &pkgs[i]);
		array_release(&pkgs[i]);
	}
	free(pkgs);
}

struct razor_set *
razor_importer_finish(struct razor_importer *importer)
{
	struct razor_set *set;
	uint32_t *map, *rmap;
	int i, count;

	map = uniqueify_properties(importer->set);
	list_remap_pool(&importer->set->property_pool, map);
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
	list_remap_pool(&importer->set->package_pool, rmap);
	build_package_file_lists(importer->set, rmap);
	remap_property_package_links(&importer->set->properties, rmap);
	free(rmap);

	set = importer->set;
	hashtable_release(&importer->table);
	free(importer);

	return set;
}

struct razor_package_iterator {
	struct razor_set *set;
	struct razor_package *package, *end;
	struct list *index;
};

struct razor_package_iterator *
razor_package_iterator_create_with_index(struct razor_set *set,
					 struct list *index)
{
	struct razor_package_iterator *pi;

	pi = zalloc(sizeof *pi);
	pi->set = set;
	pi->index = index;

	return pi;
}

struct razor_package_iterator *
razor_package_iterator_create(struct razor_set *set)
{
	struct razor_package_iterator *pi;

	pi = zalloc(sizeof *pi);
	pi->set = set;
	pi->end = set->packages.data + set->packages.size;
	pi->package = set->packages.data;

	return pi;
}

struct razor_package_iterator *
razor_package_iterator_create_for_property(struct razor_set *set,
					   struct razor_property *property)
{
	struct list *index;

	index = list_first(&property->packages, &set->package_pool);
	return razor_package_iterator_create_with_index(set, index);
}

int
razor_package_iterator_next(struct razor_package_iterator *pi,
			    struct razor_package **package,
			    const char **name, const char **version)
{
	char *pool;
	int valid;
	struct razor_package *p, *packages;

	if (pi->package) {
		p = pi->package++;
		valid = p < pi->end;
	} else if (pi->index) {
		packages = pi->set->packages.data;
		p = &packages[pi->index->data];
		pi->index = list_next(pi->index);
		valid = 1;
	} else
		valid = 0;

	if (valid) {
		pool = pi->set->string_pool.data;
		*package = p;
		*name = &pool[p->name];
		*version = &pool[p->version];
	} else {
		*package = NULL;
	}

	return valid;
}

void
razor_package_iterator_destroy(struct razor_package_iterator *pi)
{
	free(pi);
}

struct razor_package *
razor_set_get_package(struct razor_set *set, const char *package)
{
	struct razor_package_iterator *pi;
	struct razor_package *p;
	const char *name, *version;

	pi = razor_package_iterator_create(set);
	while (razor_package_iterator_next(pi, &p, &name, &version)) {
		if (strcmp(package, name) == 0)
			break;
	}
	razor_package_iterator_destroy(pi);

	return p;
}

struct razor_property_iterator {
	struct razor_set *set;
	struct razor_property *property, *end;
	struct list *index;
};

struct razor_property_iterator *
razor_property_iterator_create(struct razor_set *set,
			       struct razor_package *package)
{
	struct razor_property_iterator *pi;

	pi = zalloc(sizeof *pi);
	pi->set = set;

	if (package) {
		pi->index = list_first(&package->properties,
				       &set->property_pool);
	} else {
		pi->property = set->properties.data;
		pi->end = set->properties.data + set->properties.size;
	}

	return pi;
}

int
razor_property_iterator_next(struct razor_property_iterator *pi,
			     struct razor_property **property,
			     const char **name,
			     enum razor_version_relation *relation,
			     const char **version,
			     enum razor_property_type *type)
{
	char *pool;
	int valid;
	struct razor_property *p, *properties;

	if (pi->property) {
		p = pi->property++;
		valid = p < pi->end;
	} else if (pi->index) {
		properties = pi->set->properties.data;
		p = &properties[pi->index->data];
		pi->index = list_next(pi->index);
		valid = 1;
	} else
		valid = 0;

	if (valid) {
		pool = pi->set->string_pool.data;
		*property = p;
		*name = &pool[p->name];
		*relation = p->relation;
		*version = &pool[p->version];
		*type = p->type;
	} else {
		*property = NULL;
	}

	return valid;
}

void
razor_property_iterator_destroy(struct razor_property_iterator *pi)
{
	free(pi);
}

static struct razor_entry *
find_entry(struct razor_set *set, struct razor_entry *dir, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->string_pool.data;
	int len;

	e = (struct razor_entry *) set->files.data + dir->start;
	do {
		n = pool + e->name;
		if (strcmp(pattern + 1, n) == 0)
			return e;
		len = strlen(n);
		if (e->start != 0 && strncmp(pattern + 1, n, len) == 0 &&
		    pattern[len + 1] == '/') {
			return find_entry(set, e, pattern + len + 1);
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));

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
		n = pool + e->name;
		if (pattern && pattern[0] && fnmatch(pattern, n, 0) != 0)
			continue;
		printf("%s/%s%s\n", prefix, n, e->start > 0 ? "/" : "");
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));
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

struct razor_package_iterator *
razor_package_iterator_create_for_file(struct razor_set *set,
				       const char *filename)
{
	struct razor_entry *entry;
	struct list *index;

	entry = find_entry(set, set->files.data, filename);
	if (entry == NULL)
		return NULL;
	
	index = list_first(&entry->packages, &set->package_pool);
	return razor_package_iterator_create_with_index(set, index);
}

static struct list *
list_package_files(struct razor_set *set, struct list *r,
		   struct razor_entry *dir, uint32_t end,
		   char *prefix)
{
	struct razor_entry *e, *f, *entries;
	uint32_t next, file;
	char *pool;
	int len;
	
	entries = (struct razor_entry *) set->files.data;
	pool = set->string_pool.data;

	e = entries + dir->start;
	do {
		if (entries + r->data == e) {
			printf("%s/%s\n", prefix, pool + e->name);
			r = list_next(r);
			if (!r)
				return NULL;
			if (r->data >= end)
				return r;
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));

	e = entries + dir->start;
	do {
		if (e->start == 0)
			continue;

		if (e->flags & RAZOR_ENTRY_LAST)
			next = end;
		else {
			f = e + 1; 
			while (f->start == 0 && !(f->flags & RAZOR_ENTRY_LAST))
				f++;
			if (f->start == 0)
				next = end;
			else
				next = f->start;
		}

		file = r->data;
		if (e->start <= file && file < next) {
			len = strlen(prefix);
			prefix[len] = '/';
			strcpy(prefix + len + 1, pool + e->name);
			r = list_package_files(set, r, e, next, prefix);
			prefix[len] = '\0';
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST) && r != NULL);

	return r;
}

void
razor_set_list_package_files(struct razor_set *set, const char *name)
{
	struct razor_package *package;
	struct list *r;
	uint32_t end;
	char buffer[512];

	package = razor_set_get_package(set, name);

	r = list_first(&package->files, &set->file_pool);
	end = set->files.size / sizeof (struct razor_entry);
	buffer[0] = '\0';
	list_package_files(set, r, set->files.data, end, buffer);
}

static void
razor_set_validate(struct razor_set *set, struct array *unsatisfied)
{
	struct razor_property *r, *p, *end;
	uint32_t *u;
	char *pool;

	end = set->properties.data + set->properties.size;
	pool = set->string_pool.data;
	
	for (r = set->properties.data, p = r; r < end; r++) {
		if (r->type != RAZOR_PROPERTY_REQUIRES)
			continue;

		if (r->name != p->name) {
			p = r;
			while (p < end && p->name == r->name &&
			       p->type == r->type)
				p++;
		}

		/* If there is more than one version of a provides,
		 * seek to the end for the highest version. */
		/* FIXME: This doesn't work if we have a series of
		 * requires a = 1, provides a = 1, requires a = 2,
		 * provides a = 2, as the kernel and kernel-devel
		 * does.*/
		while (p + 1 < end && p->name == (p + 1)->name &&
		       p->type == (p + 1)->type)
			p++;

		/* FIXME: We need to track property flags (<, <=, =
		 * etc) to properly determine if a requires is
		 * satisfied.  The current code doesn't track that the
		 * requires a = 1 isn't satisfied by a = 2 provides. */

		if (p == end ||
		    p->type != RAZOR_PROPERTY_PROVIDES ||
		    r->name != p->name ||
		    versioncmp(&pool[r->version], &pool[p->version]) > 0) {
			/* FIXME: We ignore file requires for now. */
			if (pool[r->name] == '/')
				continue;
			u = array_add(unsatisfied, sizeof *u);
			*u = r - (struct razor_property *) set->properties.data;
		}
	}
}

void
razor_set_list_unsatisfied(struct razor_set *set)
{
	struct array unsatisfied;
	struct razor_property *properties, *r;
	uint32_t *u, *end;
	char *pool;

	array_init(&unsatisfied);
	razor_set_validate(set, &unsatisfied);

	end = unsatisfied.data + unsatisfied.size;
	properties = set->properties.data;
	pool = set->string_pool.data;

	for (u = unsatisfied.data; u < end; u++) {
		r = properties + *u;
		if (pool[r->version] == '\0')
			printf("%ss not satisfied\n",
			       &pool[r->name]);
		else
			printf("%s-%s not satisfied\n",
			       &pool[r->name],
			       &pool[r->version]);
	}

	array_release(&unsatisfied);
}

#define UPSTREAM_SOURCE 0x80

struct source {
	struct razor_set *set;
	uint32_t *property_map;
};

struct razor_merger {
	struct razor_set *set;
	struct hashtable table;
	struct source source1;
	struct source source2;
};

static struct razor_merger *
razor_merger_create(struct razor_set *set1, struct razor_set *set2)
{
	struct razor_merger *merger;
	int count;
	size_t size;

	merger = zalloc(sizeof *merger);
	merger->set = razor_set_create();
	hashtable_init(&merger->table, &merger->set->string_pool);

	count = set1->properties.size / sizeof (struct razor_property);
	size = count * sizeof merger->source1.property_map[0];
	merger->source1.property_map = zalloc(size);
	merger->source1.set = set1;

	count = set2->properties.size / sizeof (struct razor_property);
	size = count * sizeof merger->source2.property_map[0];
	merger->source2.property_map = zalloc(size);
	merger->source2.set = set2;

	return merger;
}

static void
add_package(struct razor_merger *merger,
	    struct razor_package *package, struct source *source,
	    uint32_t flags)
{
	char *pool;
	struct list *r;
	struct razor_package *p;

	pool = source->set->string_pool.data;
	p = array_add(&merger->set->packages, sizeof *p);
	p->name = hashtable_tokenize(&merger->table, &pool[package->name]);
	p->flags = flags;
	p->version = hashtable_tokenize(&merger->table,
					&pool[package->version]);
	p->properties = package->properties;

	r = list_first(&package->properties, &source->set->property_pool);
	while (r) {
		source->property_map[r->data] = 1;
		r = list_next(r);
	}
}


/* Build the new package list sorted by merging the two package lists.
 * Build new string pool as we go. */
static void
merge_packages(struct razor_merger *merger, struct array *packages)
{
	struct razor_package *upstream_packages, *p, *s, *send;
	struct source *source1, *source2;
	char *spool, *upool;
	uint32_t *u, *uend;
	int cmp;

	source1 = &merger->source1;
	source2 = &merger->source2;
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
			add_package(merger, s, source1, 0);
			s++;
		} else if (cmp == 0) {
			add_package(merger, p, source2, UPSTREAM_SOURCE);
			s++;
			u++;
		} else {
			add_package(merger, p, source2, UPSTREAM_SOURCE);
			u++;
		}
	}
}

static uint32_t
add_property(struct razor_merger *merger,
	     const char *name, enum razor_version_relation relation,
	     const char *version, int type)
{
	struct razor_property *p;

	p = array_add(&merger->set->properties, sizeof *p);
	p->name = hashtable_tokenize(&merger->table, name);
	p->flags = 0;
	p->type = type;
	p->relation = relation;
	p->version = hashtable_tokenize(&merger->table, version);

	return p - (struct razor_property *) merger->set->properties.data;
}

static void
merge_properties(struct razor_merger *merger)
{
	struct razor_property *p1, *p2;
	struct razor_set *set1, *set2;
	uint32_t *map1, *map2;
	int i, j, cmp, count1, count2;
	char *pool1, *pool2;

	set1 = merger->source1.set;
	set2 = merger->source2.set;
	map1 = merger->source1.property_map;
	map2 = merger->source2.property_map;

	i = 0;
	j = 0;
	pool1 = set1->string_pool.data;
	pool2 = set2->string_pool.data;

	count1 = set1->properties.size / sizeof *p1;
	count2 = set2->properties.size / sizeof *p2;
	while (i < count1 || j < count2) {
		if (i < count1 && map1[i] == 0) {
			i++;
			continue;
		}
		if (j < count2 && map2[j] == 0) {
			j++;
			continue;
		}
		p1 = (struct razor_property *) set1->properties.data + i;
		p2 = (struct razor_property *) set2->properties.data + j;
		if (i < count1 && j < count2)
			cmp = strcmp(&pool1[p1->name], &pool2[p2->name]);
		else if (i < count1)
			cmp = -1;
		else
			cmp = 1;
		if (cmp == 0)
			cmp = p1->type - p2->type;
		if (cmp == 0)
			cmp = p1->relation - p2->relation;
		if (cmp == 0)
			cmp = versioncmp(&pool1[p1->version],
					 &pool2[p2->version]);
		if (cmp < 0) {
			map1[i++] = add_property(merger,
						 &pool1[p1->name],
						 p1->relation,
						 &pool1[p1->version],
						 p1->type);
		} else if (cmp > 0) {
			map2[j++] = add_property(merger,
						 &pool2[p2->name],
						 p2->relation,
						 &pool2[p2->version],
						 p2->type);
		} else  {
			map1[i++] = map2[j++] = add_property(merger,
							     &pool1[p1->name],
							     p1->relation,
							     &pool1[p1->version],
							     p1->type);
		}
	}
}

static void
emit_properties(struct list_head *properties, struct array *source_pool,
		uint32_t *map, struct array *pool)
{
	uint32_t r;
	struct list *p, *q;

	r = pool->size / sizeof *q;
	p = list_first(properties, source_pool);
	while (p) {
		q = array_add(pool, sizeof *q);
		q->data = map[p->data];
		q->flags = p->flags;
		p = list_next(p);
	}

	list_set_ptr(properties, r);
}
	
/* Rebuild property->packages maps.  We can't just remap these, as a
 * property may have lost or gained a number of packages.  Allocate an
 * array per property and loop through the packages and add them to
 * the arrays for their properties. */
static void
rebuild_package_lists(struct razor_set *set)
{
	struct array *pkgs, *a;
	struct razor_package *pkg, *pkg_end;
	struct razor_property *prop, *prop_end;
	struct array *pool;
	struct list *r;
	uint32_t *q;
	int count;

	count = set->properties.size / sizeof (struct razor_property);
	pkgs = zalloc(count * sizeof *pkgs);
	pkg_end = set->packages.data + set->packages.size;
	pool = &set->property_pool;

	for (pkg = set->packages.data; pkg < pkg_end; pkg++) {
		r = list_first(&pkg->properties, pool);
		while (r) {
			q = array_add(&pkgs[r->data], sizeof *q);
			*q = pkg - (struct razor_package *) set->packages.data;
			r = list_next(r);
		}
	}

	prop_end = set->properties.data + set->properties.size;
	a = pkgs;
	for (prop = set->properties.data; prop < prop_end; prop++, a++) {
		list_set_array(&prop->packages, pool, a);
		array_release(a);
	}
	free(pkgs);
}

struct razor_set *
razor_merger_finish(struct razor_merger *merger)
{
	struct razor_set *result;

	result = merger->set;
	hashtable_release(&merger->table);
	free(merger);

	return result;
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
	struct razor_merger *merger;
	struct razor_package *p, *pend;

	merger = razor_merger_create(set, upstream);

	merge_packages(merger, packages);

	/* As we built the package list, we filled out a bitvector of
	 * the properties that are referenced by the packages in the
	 * new set.  Now we do a parallel loop through the properties
	 * and emit those marked in the bit vector to the new set.  In
	 * the process, we update the bit vector to actually map from
	 * indices in the old property list to indices in the new
	 * property list for both sets. */

	merge_properties(merger);

	/* Now we loop through the packages again and emit the
	 * property lists, remapped to point to the new properties. */

	pend = merger->set->packages.data + merger->set->packages.size;
	for (p = merger->set->packages.data; p < pend; p++) {
		struct source *src;

		if (p->flags & UPSTREAM_SOURCE)
			src = &merger->source2;
		else
			src = &merger->source1;

		emit_properties(&p->properties,
				&src->set->property_pool,
				src->property_map,
				&merger->set->property_pool);
		p->flags &= ~UPSTREAM_SOURCE;
	}

	rebuild_package_lists(merger->set);

	return razor_merger_finish(merger);
}

void
razor_set_satisfy(struct razor_set *set, struct array *unsatisfied,
		  struct razor_set *upstream, struct array *list)
{
	struct razor_property *requires, *r;
	struct razor_property *p, *pend;
	uint32_t *u, *end, *pkg;
	struct array *package_pool;
	char *pool, *upool;

	end = unsatisfied->data + unsatisfied->size;
	requires = set->properties.data;
	pool = set->string_pool.data;

	p = upstream->properties.data;
	pend = upstream->properties.data + upstream->properties.size;
	upool = upstream->string_pool.data;
	package_pool = &upstream->package_pool;

	for (u = unsatisfied->data; u < end; u++) {
		r = requires + *u;

		while (p < pend &&
		       strcmp(&pool[r->name], &upool[p->name]) > 0 &&
		       p->type != RAZOR_PROPERTY_PROVIDES)
			p++;
		/* If there is more than one version of a provides,
		 * seek to the end for the highest version. */
		while (p + 1 < pend && p->name == (p + 1)->name && p->type == (p + 1)->type)
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
			*pkg = list_first(&p->packages, package_pool)->data;
		}
	}	
}

static void
find_packages(struct razor_set *set,
	      int count, const char **package_names, struct array *list)
{
	struct razor_package_iterator *pi;
	struct razor_package *p, *packages;
	const char *name, *version;
	uint32_t *r;
	int i;

	packages = (struct razor_package *) set->packages.data;
	pi = razor_package_iterator_create(set);

	while (razor_package_iterator_next(pi, &p, &name, &version)) {
		for (i = 0; i < count; i++) {
			if (strcmp(name, package_names[i]) == 0) {
				r = array_add(list, sizeof *r);
				*r = p - packages;
				break;
			}
		}
	}

	razor_package_iterator_destroy(pi);
}

static void
find_all_packages(struct razor_set *set,
		  struct razor_set *upstream, struct array *list)
{
	struct razor_package *p, *u, *pend, *uend;
	uint32_t *r;
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
	uint32_t *u, *end;
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
	struct razor_package_iterator *pi1, *pi2;
	struct razor_package *p1, *p2;
	const char *name1, *name2, *version1, *version2;
	int res;

	pi1 = razor_package_iterator_create(set);
	pi2 = razor_package_iterator_create(upstream);

	razor_package_iterator_next(pi1, &p1, &name1, &version1);
	razor_package_iterator_next(pi2, &p2, &name2, &version2);

	while (p1 || p2) {
		if (p1 && p2) {
			res = strcmp(name1, name2);
			if (res == 0)
				res = versioncmp(version1, version2);
		} else {
			res = 0;
		}

		if (p2 == NULL || res < 0)
			callback(name1, version1, NULL, data);
		else if (p1 == NULL || res > 0)
			callback(name2, NULL, version2, data);

		if (p1 != NULL && res <= 0)
			razor_package_iterator_next(pi1, &p1,
						    &name1, &version1);
		if (p2 != NULL && res >= 0)
			razor_package_iterator_next(pi2, &p2,
						    &name2, &version2);
	}

	razor_package_iterator_destroy(pi1);
	razor_package_iterator_destroy(pi2);
}
