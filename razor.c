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
razor_build_evr(char *evr_buf, int size, const char *epoch,
		const char *version, const char *release)
{
	int len;

	if (!version || !*version) {
		*evr_buf = '\0';
		return;
	}

	if (epoch && *epoch && strcmp(epoch, "0") != 0) {
		len = snprintf(evr_buf, size, "%s:", epoch);
		evr_buf += len;
		size -= len;
	}
	len = snprintf(evr_buf, size, "%s", version);
	evr_buf += len;
	size -= len;
	if (release && *release)
		snprintf(evr_buf, size, "-%s", release);
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
		       &importer->properties,
		       1);

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

static uint32_t *
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

	if (up != rp)
		up++;
	set->properties.size = (void *) up - set->properties.data;
	rp_end = up;
	for (rp = set->properties.data, p = pkgs; rp < rp_end; rp++, p++) {
		list_set_array(&rp->packages, &set->package_pool, p, 0);
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
	const char *n1 = e1->name;
	const char *n2 = e2->name;

	/* Need to make sure that the contents of a directory
	 * are sorted immediately after it. So "foo/bar" has to
	 * sort before "foo.conf"
	 *
	 * FIXME: this is about 60% slower than strcmp
	 */
	while (*n1 && *n2) {
		if (*n1 < *n2)
			return *n2 == '/' ? 1 : -1;
		else if (*n1 > *n2)
			return *n1 == '/' ? -1 : 1;
		n1++;
		n2++;
	}
	if (*n1)
		return 1;
	else if (*n2)
		return -1;
	else
		return 0;
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

		list_set_array(&e->packages, &set->package_pool, &p->packages, 0);
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
	e->start = importer->files.size ? 1 : 0;
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
		list_set_array(&packages[i].files, &set->file_pool, &pkgs[i], 0);
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

static struct razor_package_iterator *
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
	 char *prefix, const char *pattern)
{
	struct razor_entry *e;
	const char *n, *pool = set->string_pool.data;

	e = (struct razor_entry *) set->files.data + dir->start;
	do {
		n = pool + e->name;
		if (pattern && pattern[0] && fnmatch(pattern, n, 0) != 0)
			continue;
		printf("%s/%s\n", prefix, n);
		if (e->start) {
			char *sub = prefix + strlen (prefix);
			*sub = '/';
			strcpy (sub + 1, n);
			list_dir(set, e, prefix, pattern);
			*sub = '\0';
		}
	} while (!((e++)->flags & RAZOR_ENTRY_LAST));
}

void
razor_set_list_files(struct razor_set *set, const char *pattern)
{
	struct razor_entry *e;
	char buffer[512], *p, *base;

	if (pattern == NULL || !strcmp (pattern, "/")) {
		buffer[0] = '\0';
		list_dir(set, set->files.data, buffer, NULL);
		return;
	}

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

		p = r;
		while (p < end && p->name == r->name &&
		       p->type == r->type)
			p++;

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
	uint32_t *file_map;
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

	merger->source1.set = set1;
	count = set1->properties.size / sizeof (struct razor_property);
	size = count * sizeof merger->source1.property_map[0];
	merger->source1.property_map = zalloc(size);
	count = set1->files.size / sizeof (struct razor_entry);
	size = count * sizeof merger->source1.file_map[0];
	merger->source1.file_map = zalloc(size);

	merger->source2.set = set2;
	count = set2->properties.size / sizeof (struct razor_property);
	size = count * sizeof merger->source2.property_map[0];
	merger->source2.property_map = zalloc(size);
	count = set2->files.size / sizeof (struct razor_entry);
	size = count * sizeof merger->source2.file_map[0];
	merger->source2.file_map = zalloc(size);

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

	p->files = package->files;
	r = list_first(&package->files, &source->set->file_pool);
	while (r) {
		source->file_map[r->data] = 1;
		r = list_next(r);
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

static uint32_t
add_file(struct razor_merger *merger, const char *name)
{
	struct razor_entry *e;

	e = array_add(&merger->set->files, sizeof *e);
	e->name = hashtable_tokenize(&merger->table, name);
	e->flags = 0;
	e->start = 0;

	return e - (struct razor_entry *)merger->set->files.data;
}

/* FIXME. Blah */
static int
fix_file_map(uint32_t *map,
	     struct razor_entry *files,
	     struct razor_entry *top)
{
	uint32_t e;
	int found_file = 0;

	e = top->start;
	do {
		if (files[e].start)
			fix_file_map(map, files, &files[e]);
		if (map[e])
			found_file = 1;
	} while (!(files[e++].flags & RAZOR_ENTRY_LAST));

	if (found_file)
		map[top - files] = 1;
	return found_file;
}

struct merge_directory {
	uint32_t merged, dir1, dir2;
};

static void
merge_one_directory(struct razor_merger *merger, struct merge_directory *md)
{
	struct razor_entry *root1, *root2, *mroot, *e1, *e2;
	struct razor_set *set1, *set2;
	struct array merge_stack;
	struct merge_directory *child_md, *end_md;
	uint32_t *map1, *map2, start, last;
	int cmp;
	char *pool1, *pool2;

	set1 = merger->source1.set;
	set2 = merger->source2.set;
	map1 = merger->source1.file_map;
	map2 = merger->source2.file_map;
	pool1 = set1->string_pool.data;
	pool2 = set2->string_pool.data;
	root1 = (struct razor_entry *) set1->files.data;
	root2 = (struct razor_entry *) set2->files.data;

	array_init(&merge_stack);

	start = merger->set->files.size / sizeof (struct razor_entry);
	last = 0;
	e1 = md->dir1 ? root1 + md->dir1 : NULL;
	e2 = md->dir2 ? root2 + md->dir2 : NULL;
	while (e1 || e2) {
		if (!e2 && !map1[e1 - root1]) {
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
			continue;
		}
		if (!e1 && !map2[e2 - root2]) {
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
			continue;
		}
		if (e1 && !map1[e1 - root1] &&
		    e2 && !map1[e2 - root2]) {
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
			continue;
		}

		if (!e1)
			cmp = 1;
		else if (!e2)
			cmp = -1;
		else {
			cmp = strcmp (&pool1[e1->name],
				      &pool2[e2->name]);
		}

		if (cmp < 0) {
			if (map1[e1 - root1]) {
				map1[e1 - root1] = last =
					add_file(merger, &pool1[e1->name]);
				if (e1->start) {
					child_md = array_add(&merge_stack, sizeof (struct merge_directory));
					child_md->merged = last;
					child_md->dir1 = e1->start;
					child_md->dir2 = 0;
				}
			}
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
		} else if (cmp > 0) {
			if (map2[e2 - root2]) {
				map2[e2 - root2] = last =
					add_file(merger, &pool2[e2->name]);
				if (e2->start) {
					child_md = array_add(&merge_stack, sizeof (struct merge_directory));
					child_md->merged = last;
					child_md->dir1 = 0;
					child_md->dir2 = e2->start;
				}
			}
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
		} else {
			map1[e1 - root1] = map2[e2- root2] = last =
				add_file(merger, &pool1[e1->name]);
			if (e1->start || e2->start) {
				child_md = array_add(&merge_stack, sizeof (struct merge_directory));
				child_md->merged = last;
				child_md->dir1 = e1->start;
				child_md->dir2 = e2->start;
			}
			if ((e1++)->flags & RAZOR_ENTRY_LAST)
				e1 = NULL;
			if ((e2++)->flags & RAZOR_ENTRY_LAST)
				e2 = NULL;
		}
	}

	mroot = (struct razor_entry *)merger->set->files.data;
	if (last) {
		mroot[last].flags = RAZOR_ENTRY_LAST;
		mroot[md->merged].start = start;
	} else
		mroot[md->merged].start = 0;

	end_md = merge_stack.data + merge_stack.size;
	for (child_md = merge_stack.data; child_md < end_md; child_md++)
		merge_one_directory(merger, child_md);
	array_release(&merge_stack);
}

static void
merge_files(struct razor_merger *merger)
{
	struct razor_entry *root;
	struct merge_directory md;
	uint32_t *map1, *map2;

	map1 = merger->source1.file_map;
	map2 = merger->source2.file_map;

	md.merged = add_file(merger, "");

	if (merger->source1.set->files.size) {
		root = (struct razor_entry *) merger->source1.set->files.data;
		if (root->start)
			fix_file_map(map1, root, root);
		md.dir1 = root->start;
	} else
		md.dir1 = 0;

	if (merger->source2.set->files.size) {
		root = (struct razor_entry *) merger->source2.set->files.data;
		if (root->start)
			fix_file_map(map2, root, root);
		md.dir2 = root->start;
	} else
		md.dir2 = 0;

	merge_one_directory(merger, &md);
}

static void
emit_files(struct list_head *files, struct array *source_pool,
	   uint32_t *map, struct array *pool)
{
	uint32_t r;
	struct list *p, *q;

	r = pool->size / sizeof *q;
	p = list_first(files, source_pool);
	while (p) {
		q = array_add(pool, sizeof *q);
		q->data = map[p->data];
		q->flags = p->flags;
		p = list_next(p);
	}

	list_set_ptr(files, r);
}

/* Rebuild property->packages maps.  We can't just remap these, as a
 * property may have lost or gained a number of packages.  Allocate an
 * array per property and loop through the packages and add them to
 * the arrays for their properties. */
static void
rebuild_property_package_lists(struct razor_set *set)
{
	struct array *pkgs, *a;
	struct razor_package *pkg, *pkg_end;
	struct razor_property *prop, *prop_end;
	struct list *r;
	uint32_t *q;
	int count;

	count = set->properties.size / sizeof (struct razor_property);
	pkgs = zalloc(count * sizeof *pkgs);
	pkg_end = set->packages.data + set->packages.size;

	for (pkg = set->packages.data; pkg < pkg_end; pkg++) {
		r = list_first(&pkg->properties, &set->property_pool);
		while (r) {
			q = array_add(&pkgs[r->data], sizeof *q);
			*q = pkg - (struct razor_package *) set->packages.data;
			r = list_next(r);
		}
	}

	prop_end = set->properties.data + set->properties.size;
	a = pkgs;
	for (prop = set->properties.data; prop < prop_end; prop++, a++) {
		list_set_array(&prop->packages, &set->package_pool, a, 0);
		array_release(a);
	}
	free(pkgs);
}

static void
rebuild_file_package_lists(struct razor_set *set)
{
	struct array *pkgs, *a;
	struct razor_package *pkg, *pkg_end;
	struct razor_entry *entry, *entry_end;
	struct list *r;
	uint32_t *q;
	int count;

	count = set->files.size / sizeof (struct razor_entry);
	pkgs = zalloc(count * sizeof *pkgs);
	pkg_end = set->packages.data + set->packages.size;

	for (pkg = set->packages.data; pkg < pkg_end; pkg++) {
		r = list_first(&pkg->files, &set->file_pool);
		while (r) {
			q = array_add(&pkgs[r->data], sizeof *q);
			*q = pkg - (struct razor_package *) set->packages.data;
			r = list_next(r);
		}
	}

	entry_end = set->files.data + set->files.size;
	a = pkgs;
	for (entry = set->files.data; entry < entry_end; entry++, a++) {
		list_set_array(&entry->packages, &set->package_pool, a, 0);
		array_release(a);
	}
	free(pkgs);
}

static struct razor_set *
razor_merger_finish(struct razor_merger *merger)
{
	struct razor_set *result;
	struct razor_package *p, *pend;

	/* As we built the package list, we filled out a bitvector of
	 * the properties that are referenced by the packages in the
	 * new set.  Now we do a parallel loop through the properties
	 * and emit those marked in the bit vector to the new set.  In
	 * the process, we update the bit vector to actually map from
	 * indices in the old property list to indices in the new
	 * property list for both sets. */

	merge_properties(merger);
	merge_files(merger);

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
		emit_files(&p->files,
			   &src->set->file_pool,
			   src->file_map,
			   &merger->set->file_pool);
		p->flags &= ~UPSTREAM_SOURCE;
	}

	rebuild_property_package_lists(merger->set);
	rebuild_file_package_lists(merger->set);

	result = merger->set;
	hashtable_release(&merger->table);
	free(merger);

	return result;
}


struct razor_transaction_resolver {
	struct razor_set *system, *upstream;
	struct bitarray syspkgs, uppkgs;
	struct array packages;
	int errors;
};

static void
find_packages(struct razor_transaction_resolver *trans,
	      int count, const char **package_names,
	      enum razor_transaction_package_state state)
{
	struct razor_set *set;
	struct bitarray *pkgbits;
	struct razor_package_iterator *pi;
	struct razor_package *p, *packages;
	const char *name, *version;
	struct razor_transaction_package *tp;
	int i, *found;

	if (state == RAZOR_PACKAGE_INSTALL) {
		set = trans->upstream;
		pkgbits = &trans->uppkgs;
	} else {
		set = trans->system;
		pkgbits = &trans->syspkgs;
	}

	packages = (struct razor_package *) set->packages.data;
	pi = razor_package_iterator_create(set);
	found = zalloc(count * sizeof (int));

	while (razor_package_iterator_next(pi, &p, &name, &version)) {
		for (i = 0; i < count; i++) {
			if (strcmp(name, package_names[i]) == 0) {
				found[i] = 1;
				tp = array_add(&trans->packages, sizeof *tp);
				memset(tp, 0, sizeof *tp);
				tp->package = p;
				tp->name = name;
				tp->version = version;
				tp->state = state;
				bitarray_set(pkgbits, p - packages,
					     state == RAZOR_PACKAGE_INSTALL);
				break;
			}
		}
	}

	for (i = 0; i < count; i++) {
		if (!found[i]) {
			tp = array_add(&trans->packages, sizeof *tp);
			memset(tp, 0, sizeof *tp);
			tp->name = strdup(package_names[i]);
			tp->state = state | RAZOR_PACKAGE_UNAVAILABLE;
			trans->errors++;
		}
	}

	razor_package_iterator_destroy(pi);
	free(found);
}

static void
find_all_packages(struct razor_transaction_resolver *trans)
{
	struct razor_transaction_package *tp;
	struct razor_package *p, *packages, *u, *pend, *uend;
	char *pool, *upool;

	packages = trans->system->packages.data;
	pend = trans->system->packages.data + trans->system->packages.size;
	pool = trans->system->string_pool.data;
	u = trans->upstream->packages.data;
	uend = trans->upstream->packages.data + trans->upstream->packages.size;
	upool = trans->upstream->string_pool.data;

	for (p = packages; p < pend; p++) {
		while (u < uend && strcmp(&pool[p->name], &upool[u->name]) > 0)
			u++;
		if (strcmp(&pool[p->name], &upool[u->name]) == 0) {
			tp = array_add(&trans->packages, sizeof *tp);
			memset(tp, 0, sizeof *tp);
			tp->name = &upool[u->name];
			tp->version = &upool[u->version];
			tp->state = RAZOR_PACKAGE_INSTALL;
			bitarray_set(&trans->uppkgs, p - packages, 1);
		}
	}
}

/* FIXME: wrong, need to compare names, not razor_package* */
static int
find_transaction_package(struct array *package_array,
			 struct razor_package *package)
{
	struct razor_transaction_package *tps = package_array->data;
	int i, tpcount = package_array->size / sizeof *tps;

	for (i = 0; i < tpcount; i++) {
		if (tps[i].package == package)
			return i;
	}
	return -1;
}

static int
provider_satisfies_requirement(struct razor_property *provider,
			       const char *provider_strings,
			       struct razor_property *requirement,
			       const char *requirement_strings)
{
	int cmp, len;
	const char *provided = &provider_strings[provider->version];
	const char *required = &requirement_strings[requirement->version];

	if (!*required)
		return 1;

	cmp = versioncmp(provided, required);

	switch (requirement->relation) {
	case RAZOR_VERSION_LESS:
		return cmp < 0;

	case RAZOR_VERSION_LESS_OR_EQUAL:
		if (cmp <= 0)
			return 1;
		/* fall through: FIXME, make sure this is correct */

	case RAZOR_VERSION_EQUAL:
		if (cmp == 0)
			return 1;

		/* "foo == 1.1" is satisfied by "foo 1.1-2" */
		len = strlen(required);
		if (!strncmp(required, provided, len) && provided[len] == '-')
			return 1;
		return 0;

	case RAZOR_VERSION_GREATER_OR_EQUAL:
		return cmp >= 0;

	case RAZOR_VERSION_GREATER:
		return cmp > 0;
	}

	/* shouldn't happen */
	return 0;
}

static struct razor_package *
find_file(struct razor_set *set, struct bitarray *pkgbits,
	  const char *filename, int installed)
{
	struct razor_package *pkgs = set->packages.data;
	struct razor_entry *entry;
	struct list *p;

	if (filename[0] != '/')
		return 0;

	entry = find_entry(set, set->files.data, filename);
	if (!entry)
		return 0;

	for (p = list_first(&entry->packages, &set->package_pool); p; p = list_next(p)) {
		if (bitarray_get(pkgbits, p->data) == installed)
			return &pkgs[p->data];
	}
	return NULL;
}

static struct razor_package *
find_system_file(struct razor_transaction_resolver *trans,
		 const char *filename, int installed)
{
	return find_file(trans->system, &trans->syspkgs, filename, installed);
}

static struct razor_package *
find_upstream_file(struct razor_transaction_resolver *trans,
		   const char *filename, int installed)
{
	return find_file(trans->upstream, &trans->uppkgs, filename, installed);
}

static struct razor_package *
find_system_provider(struct razor_transaction_resolver *trans,
		     int installed, int match_name,
		     struct razor_property *req, int *sp)
{
	struct razor_package *spkgs = trans->system->packages.data;
	struct razor_property *sprops = trans->system->properties.data;
	const char *spool = trans->system->string_pool.data;
	const char *upool = trans->upstream->string_pool.data;
	int scount = trans->system->properties.size / sizeof *sprops;

	/* Skip ahead to first matching PROVIDES */
	while (*sp < scount &&
	       strcmp(&spool[sprops[*sp].name], &upool[req->name]) < 0)
		(*sp)++;
	while (*sp < scount &&
	       sprops[*sp].type != RAZOR_PROPERTY_PROVIDES &&
	       strcmp(&spool[sprops[*sp].name], &upool[req->name]) == 0)
		(*sp)++;	       

	/* Scan matching PROVIDES */
	while (*sp < scount &&
	       sprops[*sp].type == RAZOR_PROPERTY_PROVIDES &&
	       strcmp(&spool[sprops[*sp].name],
		      &upool[req->name]) == 0) {
		if (provider_satisfies_requirement(&sprops[*sp], spool,
						   req, upool)) {
			struct list *pkg;

			for (pkg = list_first(&sprops[*sp].packages, &trans->system->package_pool); pkg; pkg = list_next(pkg)) {
				if (bitarray_get(&trans->syspkgs, pkg->data) != installed)
					continue;
				if (!match_name ||
				    strcmp(&spool[spkgs[pkg->data].name],
					   &upool[req->name]) == 0)
					return &spkgs[pkg->data];
			}
		}
		(*sp)++;
	}

	return NULL;
}

static struct razor_package *
find_upstream_provider(struct razor_transaction_resolver *trans,
		       int installed, int match_name,
		       struct razor_property *req, int up)
{
	struct razor_package *upkgs = trans->upstream->packages.data;
	struct razor_property *uprops = trans->upstream->properties.data;
	const char *upool = trans->upstream->string_pool.data;
	int ucount = trans->upstream->properties.size / sizeof *uprops;

	/* Skip to first matching provide */
	if (req->type < RAZOR_PROPERTY_PROVIDES) {
		while (up < ucount &&
		       uprops[up].type != RAZOR_PROPERTY_PROVIDES)
			up++;
	} else {
		while (up >= 0 &&
		       uprops[up].type != RAZOR_PROPERTY_PROVIDES)
			up--;
		while (up > 0 &&
		       uprops[up - 1].type == RAZOR_PROPERTY_PROVIDES)
			up--;
		if (up < 0)
			return NULL;
	}

	/* Scan matching PROVIDES */
	while (up < ucount &&
	       uprops[up].type == RAZOR_PROPERTY_PROVIDES &&
	       uprops[up].name == req->name) {
		if (provider_satisfies_requirement(&uprops[up], upool,
						   req, upool)) {
			struct list *pkg;

			for (pkg = list_first(&uprops[up].packages, &trans->upstream->package_pool); pkg; pkg = list_next(pkg)) {
				if (bitarray_get(&trans->uppkgs, pkg->data) != installed)
					continue;
				if (!match_name ||
				    strcmp(&upool[upkgs[pkg->data].name],
					   &upool[req->name]) == 0)
					return &upkgs[pkg->data];
			}
		}
		up++;
	}
	return NULL;
}

static struct razor_package *
find_upgrade(struct razor_transaction_resolver *trans,
	     struct razor_property *obsolete, int up)
{
	struct razor_property *uprops = trans->upstream->properties.data;
	const char *upool = trans->upstream->string_pool.data;
	struct razor_property req;

	if (uprops[up].relation > RAZOR_VERSION_EQUAL ||
	    !upool[uprops[up].version])
		return NULL;

	memcpy(&req, obsolete, sizeof req);
	req.type = RAZOR_PROPERTY_REQUIRES;
	if (uprops[up].relation == RAZOR_VERSION_LESS)
		req.relation = RAZOR_VERSION_GREATER_OR_EQUAL;
	else
		req.relation = RAZOR_VERSION_GREATER;

	/* We need to rewind up, since OBSOLETES > PROVIDES, so we've
	 * already gone past the possible upgrades.
	 */
	while (up >= 0 &&
	       uprops[up].type != RAZOR_PROPERTY_PROVIDES)
		up--;
	while (up > 0 &&
	       uprops[up - 1].type == RAZOR_PROPERTY_PROVIDES)
		up--;
	if (up < 0)
		return NULL;

	return find_upstream_provider(trans, 0, 1, &req, up);
}

static void
add_transaction_package(struct razor_transaction_resolver *trans,
			struct razor_package *package,
			struct razor_set *package_set,
			enum razor_transaction_package_state state,
			struct razor_property *req_prop,
			struct razor_set *req_set)
{
	struct razor_transaction_package *tp;
	const char *pool;
	struct razor_package *pkgs;
	struct list *pkg;

	tp = array_add(&trans->packages, sizeof *tp);
	memset(tp, 0, sizeof *tp);

	if (package) {
		tp->package = package;
		pool = package_set->string_pool.data;
		tp->name = &pool[package->name];
		tp->version = &pool[package->version];
		tp->state = state;
	} else
		tp->state = state | RAZOR_PACKAGE_UNSATISFIABLE;

	for (pkg = list_first(&req_prop->packages, &req_set->package_pool); pkg; pkg = list_next(pkg)) {
		if (bitarray_get(&trans->uppkgs, pkg->data))
			break;
	}
	if (pkg) {
		pool = req_set->string_pool.data;
		pkgs = req_set->packages.data;
		tp->req_package = &pool[pkgs[pkg->data].name];
	}
	tp->req_type = req_prop->type;
	tp->req_property = &pool[req_prop->name];
	tp->req_relation = req_prop->relation;
	tp->req_version = &pool[req_prop->version];

	pkgs = package_set->packages.data;
	if (tp->state == RAZOR_PACKAGE_INSTALL)
		bitarray_set(&trans->uppkgs, package - pkgs, 1);
	else if (tp->state == RAZOR_PACKAGE_REMOVE)
		bitarray_set(&trans->syspkgs, package - pkgs, 0);
	else
		trans->errors++;
}

/* FIXME */
static int
prop_is_being_installed(struct razor_transaction_resolver *trans,
			struct razor_property *prop)
{
	struct list *pkg;

	for (pkg = list_first(&prop->packages, &trans->upstream->package_pool); pkg; pkg = list_next(pkg)) {
		if (bitarray_get(&trans->uppkgs, pkg->data))
			return 1;
	}
	return 0;
}

static void
razor_transaction_satisfy_installs(struct razor_transaction_resolver *trans)
{
	struct razor_package *spkgs, *upkgs, *pkg;
	struct razor_property *prop, *sprops, *uprops;
	int sp, up, ucount;
	const char *upool;

	spkgs = trans->system->packages.data;
	sprops = trans->system->properties.data;
	upkgs = trans->upstream->packages.data;
	uprops = trans->upstream->properties.data;
	ucount = trans->upstream->properties.size / sizeof *uprops;
	upool = trans->upstream->string_pool.data;

	sp = up = 0;
	while (up < ucount) {
		/* Skip 'up' ahead to a property of a package which is
		 * to-be-installed.
		 */
		while (up < ucount &&
		       (uprops[up].type == RAZOR_PROPERTY_PROVIDES ||
			!prop_is_being_installed(trans, &uprops[up])))
			up++;
		if (up == ucount)
			break;

		prop = &uprops[up];
		switch (prop->type) {
		case RAZOR_PROPERTY_REQUIRES:
			if (!strncmp(&upool[prop->name], "rpmlib(", 7))
				break;

			if (find_system_provider(trans, 1, 0, prop, &sp) ||
			    find_upstream_provider(trans, 1, 0, prop, up) ||
			    find_system_file(trans, &upool[prop->name], 1) ||
			    find_upstream_file(trans, &upool[prop->name], 1)) {
				/* Requires something that is either installed
				 * or to-be-installed.
				 */
				break;
			}

			/* See if we can install a new upstream provider */
			pkg = find_upstream_provider(trans, 0, 0, prop, up);
			if (!pkg)
				pkg = find_upstream_file(trans, &upool[prop->name], 0);
			add_transaction_package(trans, pkg, trans->upstream,
						RAZOR_PACKAGE_INSTALL,
						prop, trans->upstream);
			break;

		case RAZOR_PROPERTY_CONFLICTS:
			if ((pkg = find_system_provider(trans, 1, 1, prop, &sp))) {
				struct razor_package *upgrade;

				/* Conflicts with something already installed.
				 * Try to upgrade out.
				 */
				upgrade = find_upgrade(trans, prop, up);
				if (upgrade) {
					bitarray_set(&trans->syspkgs, pkg - spkgs, 0);
					add_transaction_package(trans, upgrade,
								trans->upstream,
								RAZOR_PACKAGE_INSTALL,
								prop, trans->upstream);
				} else {
					add_transaction_package(trans, pkg,
								trans->system, 
								RAZOR_PACKAGE_INSTALL_CONFLICT,
								prop, trans->upstream);
				}
			} else if ((pkg = find_upstream_provider(trans, 1, 1, prop, up))) {
				/* Conflicts with something already to-be-installed */
				add_transaction_package(trans, pkg,
							trans->upstream, 
							RAZOR_PACKAGE_INSTALL_CONFLICT,
							prop, trans->upstream);
			}
			break;

		case RAZOR_PROPERTY_OBSOLETES:
			if ((pkg = find_system_provider(trans, 1, 1, prop, &sp))) {
				/* Obsoletes something installed */
				add_transaction_package(trans, pkg,
							trans->system, 
							RAZOR_PACKAGE_REMOVE,
							prop, trans->upstream);
			} else if ((pkg = find_upstream_provider(trans, 1, 1, prop, up))) {
				/* Obsoletes something that was to-be-installed */
				add_transaction_package(trans, pkg,
							trans->upstream, 
							RAZOR_PACKAGE_REMOVE_CONFLICT,
							prop, trans->upstream);
			}
			break;

		default:
			/* can't happen */
			break;
		}
		up++;
	}
}

/* Look through pkg's PROVIDES, and for each one that no other package
 * provides, add its property index to lost_provides.
 */
static void
gather_lost_provides(struct razor_set *set, struct razor_package *pkg,
		     struct array *lost_provides)
{
	struct razor_property *props = set->properties.data, *prop;
	struct list *p, *providers;
	uint32_t *lost;

	for (p = list_first(&pkg->properties, &set->property_pool); p; p = list_next(p)) {
		prop = &props[p->data];
		if (prop->type != RAZOR_PROPERTY_PROVIDES)
			continue;

		providers = list_first(&prop->packages, &set->package_pool);
		if (providers && !list_next(providers)) {
			lost = array_add(lost_provides, sizeof *lost);
			*lost = p->data;
		}
	}
}

static void
gather_lost_files(struct razor_set *set, struct razor_package *pkg,
		  struct array *lost_files)
{
	struct razor_entry *entries = set->files.data, *entry, **lost;
	struct list *e, *providers;

	for (e = list_first(&pkg->files, &set->file_pool); e; e = list_next(e)) {
		entry = &entries[e->data];
		providers = list_first(&entry->packages, &set->package_pool);
		if (providers && !list_next(providers)) {
			lost = array_add(lost_files, sizeof *lost);
			*lost = entry;
		}
	}
}

static void
lose_required_package(struct razor_transaction_resolver *trans,
		      struct razor_property *req,
		      struct list_head *lost_package_list)
{
	struct razor_package *pkgs, *lost_package;
	char *pool = trans->system->string_pool.data;
	struct list *p;
	struct razor_transaction_package *tp, *packages;;
	int already;

	pkgs = trans->system->packages.data;
	lost_package = &pkgs[list_first(lost_package_list, &trans->system->package_pool)->data];

	for (p = list_first(&req->packages, &trans->system->package_pool); p; p = list_next(p)) {
		packages = trans->packages.data;
		already = find_transaction_package(&trans->packages, &pkgs[p->data]);
		if (already != -1 &&
		    (packages[already].state & RAZOR_PACKAGE_REMOVE))
			continue;

		tp = array_add(&trans->packages, sizeof *tp);
		memset(tp, 0, sizeof *tp);
		tp->package = &pkgs[p->data];
		tp->name = &pool[tp->package->name];
		tp->version = &pool[tp->package->version];
		tp->req_package = &pool[lost_package->name];
		tp->req_type = req->type;
		tp->req_property = &pool[req->name];
		tp->req_relation = req->relation;
		tp->req_version = &pool[req->version];
		if (already != -1) {
			tp->state = RAZOR_PACKAGE_REMOVE_BLOCKED;
			trans->errors++;
		} else {
			tp->state = RAZOR_PACKAGE_REMOVE;
			bitarray_set(&trans->syspkgs, p->data, 0);
		}
	}
}

static void
lose_requirement(struct razor_transaction_resolver *trans,
		 struct razor_property *req,
		 struct razor_property *lost_provider,
		 struct razor_property *first_provider)
{
	struct razor_property *provider, *prop_end;
	char *pool = trans->system->string_pool.data;

	prop_end = trans->system->properties.data + trans->system->properties.size;

	/* See if any other provider satisfies req */
	for (provider = first_provider;
	     provider < prop_end && provider->type == RAZOR_PROPERTY_PROVIDES && provider->name == lost_provider->name;
	     provider++) {
		if (provider == lost_provider)
			continue;

		if (provider_satisfies_requirement(provider, pool, req, pool))
			return;
	}

	lose_required_package(trans, req, &lost_provider->packages);
}

static void
razor_transaction_satisfy_removes(struct razor_transaction_resolver *trans,
				  int start, int end)
{
	struct razor_transaction_package *packages;
	struct razor_package *pkgs;
	int pkg_count, r;
	uint32_t *lost, *lost_end;
	struct razor_entry *entry, **lostf, **lostf_end;
	struct razor_property *props, *prop_end, *req, *first_provider;
	struct array lost_provides, lost_files;
	char *pool;

	pkgs = trans->system->packages.data;
	pkg_count = trans->system->packages.size / sizeof (struct razor_package);
	props = trans->system->properties.data;
	prop_end = trans->system->properties.data + trans->system->properties.size;
	pool = trans->system->string_pool.data;

	array_init(&lost_files);
	array_init(&lost_provides);
	for (r = start; r < end; r++) {
		packages = trans->packages.data;
		if (packages[r].state != RAZOR_PACKAGE_REMOVE)
			continue;

		gather_lost_provides(trans->system, packages[r].package,
				     &lost_provides);
		gather_lost_files(trans->system, packages[r].package,
				  &lost_files);
	}

	/* Handle lost_provides */
	lost_end = lost_provides.data + lost_provides.size;
	for (lost = lost_provides.data; lost < lost_end; lost++) {
		/* Requires FOO will appear before Provides FOO */
		for (req = &props[*lost]; req > props && req->name == props[*lost].name && req->type != RAZOR_PROPERTY_REQUIRES; req--)
			;
		first_provider = req + 1;

		while (req > props && req->name == props[*lost].name) {
			lose_requirement(trans, req, &props[*lost],
					 first_provider);
			req--;
		}
	}
	array_release(&lost_provides);

	/* And now lost_files. FIXME, inefficient */
	lostf_end = lost_files.data + lost_files.size;

	req = props;
	/* Due to the sorting of props, this loop is likely a no-op */
	while (req < prop_end && pool[req->name] != '/')
		req++;

	for (; req < prop_end && pool[req->name] == '/'; req++) {
		if (req->type != RAZOR_PROPERTY_REQUIRES)
			continue;

		entry = find_entry(trans->system, trans->system->files.data,
				   &pool[req->name]);
		if (!entry)
			continue;

		for (lostf = lost_files.data; lostf < lostf_end; lostf++) {
			if (*lostf == entry)
				break;
		}
		if (lostf == lostf_end)
			continue;

		lose_required_package(trans, req, &entry->packages);
	}
	array_release(&lost_files);
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

struct razor_transaction *
razor_transaction_create(struct razor_set *system, struct razor_set *upstream,
			 int update_count, const char **update_packages,
			 int remove_count, const char **remove_packages)
{
	struct razor_transaction_resolver trans;
	struct razor_transaction *ret_trans;
	int start, end;

	trans.system = system;
	trans.upstream = upstream ? upstream : razor_set_create();
	array_init(&trans.packages);
	bitarray_init(&trans.syspkgs, trans.system->packages.size / sizeof (struct razor_package), 1);
	bitarray_init(&trans.uppkgs, trans.upstream->packages.size / sizeof (struct razor_package), 0);
	trans.errors = 0;

	/* Find initial upstream packages to be installed */
	if (update_count > 0) {
		find_packages(&trans, update_count, update_packages,
			      RAZOR_PACKAGE_INSTALL);
	} else if (remove_count == 0)
		find_all_packages(&trans);

	/* Find initial installed packages to remove. */
	if (remove_count > 0) {
		find_packages(&trans, remove_count, remove_packages,
			      RAZOR_PACKAGE_REMOVE);
	}

	start = 0;
	end = trans.packages.size / sizeof (struct razor_transaction_package);

	while (!trans.errors && start != end) {
		razor_transaction_satisfy_installs(&trans);
		razor_transaction_satisfy_removes(&trans, start, end);

		start = end;
		end = trans.packages.size / sizeof (struct razor_transaction_package);
	}

	ret_trans = zalloc(sizeof *ret_trans);
	ret_trans->system = trans.system;
	ret_trans->upstream = trans.upstream;
	ret_trans->packages = trans.packages.data;
	ret_trans->package_count = end;
	ret_trans->errors = trans.errors;
	return ret_trans;
}

const char * const razor_version_relations[] = {
	/* same order as enum razor_version_relation */
	"<", "<=", "=", ">=", ">"
};

const char * const razor_property_types[] = {
	/* same order as enum razor_property_type */
	"requires", "provides", "conflicts with", "obsoletes"
};

const char * const razor_property_types_removal[] = {
	/* same order as enum razor_property_type */
	"required", "provided", "conflicted with", "was obsoleted by"
};

void
razor_transaction_describe(struct razor_transaction *trans)
{
	struct razor_transaction_package *p, *pend, *tps;
	int errors_only = 0;

	tps = trans->packages;
	pend = trans->packages + trans->package_count;
	for (p = trans->packages; p < pend; p++) {
		switch (p->state) {
		case RAZOR_PACKAGE_INSTALL:
			if (errors_only)
				break;

			printf ("Installing %s %s", p->name, p->version);
			if (p->req_package) {
				printf (" for %s", p->req_package);
			print_requirement:
				if (*p->req_version) {
					printf (", which %s %s %s %s",
						razor_property_types[p->req_type],
						p->req_property,
						razor_version_relations[p->req_relation],
						p->req_version);
				} else if (strcmp(p->req_property, p->name) != 0) {
					printf (", which %s %s",
						razor_property_types[p->req_type],
						p->req_property);
				}
			}
			printf("\n");
			break;

		case RAZOR_PACKAGE_INSTALL_UNAVAILABLE:
			if (*p->req_version && strcmp(p->req_property, p->name) == 0) {
				printf ("Can't find %s %s %s, which is required by %s",
					p->name,
					razor_version_relations[p->req_relation],
					p->req_version,
					p->req_package);
			} else {
				printf ("Can't find %s", p->name);
				if (*p->version)
					printf (" %s", p->version);
				
				if (p->req_package) {
					printf ("  which is required by %s",
						p->req_package);
					if (strcmp(p->req_property, p->name) != 0)
						printf (" for %s", p->req_property);
				}
			}
			printf("\n");
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_INSTALL_CONFLICT:
			printf ("Cannot install %s", p->req_package);
			errors_only = 1;
			goto print_requirement;

		case RAZOR_PACKAGE_INSTALL_UNSATISFIABLE:
			printf ("Cannot find package for %s", p->req_property);
			if (*p->req_version) {
				printf (" %s %s",
					razor_version_relations[p->req_relation],
					p->req_version);
			}
			printf (" which is required by %s\n",
				p->req_package);
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_REMOVE:
			if (errors_only)
				break;
			printf ("Removing %s %s", p->name, p->version);
			if (p->req_package) {
				printf (" which %s %s",
					razor_property_types_removal[p->req_type],
					p->req_package);
				if (strcmp(p->req_property, p->name) != 0)
					printf (" for %s", p->req_property);
			}
			printf("\n");
			break;

		case RAZOR_PACKAGE_REMOVE_NOT_INSTALLED:
			printf ("Package %s is not installed\n", p->name);
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_REMOVE_BLOCKED:
			printf ("Cannot remove %s, which is marked for installation but requires %s\n", p->name, p->req_package);
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_REMOVE_CONFLICT:
			printf ("Cannot remove %s, which is marked for installation but is obsoleted by %s\n", p->name, p->req_package);
			errors_only = 1;
			break;

		default:
			/* Shouldn't actually happen */
			break;
		}
	}
}

struct razor_set *
razor_transaction_run(struct razor_transaction *trans)
{
	struct array install_packages, remove_packages;
	struct razor_merger *merger;
	struct razor_package *pkg, *i, *iend, *r, *rend, *s, *send;
	struct source *source1, *source2;
	char *spool, *ipool, *rpool;
	uint32_t *map;
	int p, cmp;

	/* FIXME */
	if (trans->errors)
		return NULL;

	/* Sort the transaction packages into two arrays */
	array_init(&install_packages);
	array_init(&remove_packages);
	for (p = 0; p < trans->package_count; p++) {
		if (trans->packages[p].state & RAZOR_PACKAGE_INSTALL)
			pkg = array_add(&install_packages, sizeof *pkg);
		else
			pkg = array_add(&remove_packages, sizeof *pkg);
		*pkg = *trans->packages[p].package;
	}
	map = qsort_with_data(install_packages.data,
			      install_packages.size / sizeof *pkg,
			      sizeof *pkg,
			      compare_packages,
			      trans->upstream);
	free(map);
	map = qsort_with_data(remove_packages.data,
			      remove_packages.size / sizeof *pkg,
			      sizeof *pkg,
			      compare_packages,
			      trans->system);
	free(map);

	merger = razor_merger_create(trans->system, trans->upstream);

	source1 = &merger->source1;
	source2 = &merger->source2;

	i = install_packages.data;
	iend = install_packages.data + install_packages.size;
	ipool = trans->upstream->string_pool.data;

	r = remove_packages.data;
	rend = remove_packages.data + remove_packages.size;
	rpool = trans->system->string_pool.data;

	s = trans->system->packages.data;
	send = trans->system->packages.data + trans->system->packages.size;
	spool = trans->system->string_pool.data;

	while (s < send || i < iend) {
		/* Check if s is being removed */
		if (s < send && r < rend &&
		    s->name == r->name && s->version && r->version) {
			s++;
			r++;
			continue;
		}

		if (s < send && i < iend)
			cmp = strcmp(&spool[s->name], &ipool[i->name]);
		else if (s < send)
			cmp = -1;
		else
			cmp = 1;
		if (cmp < 0) {
			add_package(merger, s, source1, 0);
			s++;
		} else if (cmp == 0) {
			add_package(merger, i, source2, UPSTREAM_SOURCE);
			s++;
			i++;
		} else {
			add_package(merger, i, source2, UPSTREAM_SOURCE);
			i++;
		}
	}

	array_release(&install_packages);
	array_release(&remove_packages);

	return razor_merger_finish(merger);
}

void
razor_transaction_destroy(struct razor_transaction *trans)
{
	int p;

	for (p = 0; p < trans->package_count; p++) {
		if (!trans->packages[p].req_package &&
		    (trans->packages[p].state == RAZOR_PACKAGE_INSTALL_UNAVAILABLE ||
		     trans->packages[p].state == RAZOR_PACKAGE_REMOVE_NOT_INSTALLED))
			free((char *)trans->packages[p].name);
	}
	free(trans);

	/* FIXME: free upstream if it was created as an empty set */
}
