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
	enum razor_property_type type : 2;
	enum razor_version_relation relation : 32;
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
	struct array file_requires;
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
	struct razor_set *set;
	struct razor_entry *e;
	char *empty;

	set = zalloc(sizeof *set);

	e = array_add(&set->files, sizeof *e);
	empty = array_add(&set->string_pool, 1);
	*empty = '\0';
	e->name = 0;
	e->flags = RAZOR_ENTRY_LAST;
	e->start = 0;
	list_set_empty(&e->packages);

	return set;
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

	if (type == RAZOR_PROPERTY_REQUIRES && *name == '/') {
		r = array_add(&importer->file_requires, sizeof *r);
		*r = p->name;
	}
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

	n1 = strtol(s1, (char **) &p1, 10);
	n2 = strtol(s2, (char **) &p2, 10);

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
	e = importer->set->files.data;
	e->name = root.name;
	e->flags = RAZOR_ENTRY_LAST;
	e->start = importer->files.size ? 1 : 0;
	list_set_empty(&e->packages);

	serialize_files(importer->set, &root, &importer->set->files);

	array_release(&importer->files);
}

static struct razor_entry *
find_entry(struct razor_set *set, struct razor_entry *dir, const char *pattern);

static void
list_to_array(struct list *list, struct array *array)
{
	uint32_t *item;

	while (list) {
		 item = array_add(array, sizeof *item);
		 *item = list->data;
		 list = list_next(list);
	}
}

static int
compare_file_requires(const void *p1, const void *p2, void *data)
{
	uint32_t *f1 = (void *)p1, *f2 = (void *)p2;
	const char *pool = data;

	return strcmp(&pool[*f1], &pool[*f2]);
}

static void
find_file_provides(struct razor_importer *importer)
{
	struct razor_property *prop;
	struct razor_entry *top, *entry;
	struct razor_package *packages;
	struct array pkgprops;
	struct list *pkg;
	uint32_t *req, *req_start, *req_end;
	uint32_t *map, *newprop;
	char *pool;

	pool = importer->set->string_pool.data;
	packages = importer->set->packages.data;
	top = importer->set->files.data;

	req = req_start = importer->file_requires.data;
	req_end = importer->file_requires.data + importer->file_requires.size;
	map = qsort_with_data(req, req_end - req, sizeof *req,
			      compare_file_requires, pool);
	free(map);

	for (req = req_start; req < req_end; req++) {
		if (req > req_start && req[0] == req[-1])
			continue;
		entry = find_entry(importer->set, top, &pool[*req]);
		if (!entry)
			continue;

		for (pkg = list_first(&entry->packages, &importer->set->package_pool); pkg; pkg = list_next(pkg)) {
			prop = array_add(&importer->set->properties, sizeof *prop);
			prop->name = *req;
			prop->type = RAZOR_PROPERTY_PROVIDES;
			prop->relation = RAZOR_VERSION_EQUAL;
			prop->version = hashtable_tokenize(&importer->table, "");
			list_set_ptr(&prop->packages, pkg->data);

			/* Update property list of pkg */
			array_init(&pkgprops);
			list_to_array(list_first(&packages[pkg->data].properties, &importer->set->property_pool), &pkgprops);
			newprop = array_add(&pkgprops, sizeof *newprop);
			*newprop = prop - (struct razor_property *)importer->set->properties.data;
			list_set_array(&packages[pkg->data].properties, &importer->set->property_pool, &pkgprops, 1);
			array_release(&pkgprops);
		}
	}

	array_release(&importer->file_requires);
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

	build_file_tree(importer);
	find_file_provides(importer);

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

	md.merged = 0;

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


struct razor_transaction_resolver {
	struct razor_set *system, *upstream;
	struct bitarray syspkgs, uppkgs;
	struct array packages;
	int errors;
};

static int
package_in_set(void *package, struct razor_set *set)
{
	return package >= set->packages.data &&
		package < set->packages.data + set->packages.size;
}

static int
property_in_set(void *property, struct razor_set *set)
{
	return property >= set->properties.data &&
		property < set->properties.data + set->properties.size;
}

static struct razor_package *
property_provider_package(struct razor_transaction_resolver *trans,
			  struct razor_property *prop,
			  int installed)
{
	struct razor_set *set;
	struct bitarray *pkgbits;
	struct razor_package *pkgs;
	struct list *p;

	if (installed && prop->type != RAZOR_PROPERTY_PROVIDES)
		return NULL;
	else if (!installed &&
		 prop->type != RAZOR_PROPERTY_PROVIDES &&
		 prop->type != RAZOR_PROPERTY_OBSOLETES)
		return NULL;

	if (property_in_set(prop, trans->system)) {
		set = trans->system;
		pkgbits = &trans->syspkgs;
	} else {
		set = trans->upstream;
		pkgbits = &trans->uppkgs;
	}
	pkgs = set->packages.data;

	for (p = list_first(&prop->packages, &set->package_pool); p; p = list_next(p)) {
		if (bitarray_get(pkgbits, p->data) != installed)
			continue;
		if (prop->type == RAZOR_PROPERTY_OBSOLETES ||
		    pkgs[p->data].name == prop->name)
			return &pkgs[p->data];
	}
	return NULL;
}

static int
compare_transaction_packages(const void *one, const void *two)
{
	struct razor_transaction_package **tp1 = (void *)one;
	struct razor_transaction_package **tp2 = (void *)two;

	if (!(*tp1)->name)
		return 1;
	else if (!(*tp2)->name)
		return -1;
	else
		return strcmp((*tp1)->name, (*tp2)->name);
}

/* FIXME: merge this into the other property loop in razor_transaction_satisfy */
static void
resolve_new_packages(struct razor_transaction_resolver *trans,
		     int start, int end)
{
	struct razor_property *sp, *up, *sp_end, *up_end;
	struct razor_package *spkg, *spkgs, *upkg, *upkgs;
	struct razor_transaction_package **packages;
	const char *spool, *upool;
	int i;

	sp_end = trans->system->properties.data + trans->system->properties.size;
	spool = trans->system->string_pool.data;
	spkgs = trans->system->packages.data;
	up_end = trans->upstream->properties.data + trans->upstream->properties.size;
	upool = trans->upstream->string_pool.data;
	upkgs = trans->upstream->packages.data;

	/* FIXME, check if sorting the packages directly (rather than
	 * sorting pointers-to-packages) still results in confusing
	 * descriptions.
	 */
	packages = calloc(end - start, sizeof *packages);
	for (i = start; i < end; i++)
		packages[i - start] = ((struct razor_transaction_package *)trans->packages.data) + i;
	qsort(packages, end - start, sizeof *packages,
	      compare_transaction_packages);

	sp = trans->system->properties.data;
	up = trans->upstream->properties.data;
	for (i = 0; i < end - start; i++) {
		if (!packages[i]->name ||
		    packages[i]->state >= RAZOR_PACKAGE_FIRST_ERROR_STATE)
			continue;

		spkg = NULL;
		while (sp < sp_end &&
		       strcmp(&spool[sp->name], packages[i]->name) < 0)
			sp++;
		while (sp < sp_end &&
		       strcmp(&spool[sp->name], packages[i]->name) == 0 &&
		       !(spkg = property_provider_package(trans, sp, 1)))
			sp++;

		upkg = NULL;
		while (up < up_end &&
		       strcmp(&upool[up->name], packages[i]->name) < 0)
			up++;
		while (up < up_end &&
		       strcmp(&upool[up->name], packages[i]->name) == 0 &&
		       !(upkg = property_provider_package(trans, up, 0)))
			up++;

		if (packages[i]->state == RAZOR_PACKAGE_REMOVE ||
		    packages[i]->state == RAZOR_PACKAGE_OBSOLETED) {
			if (spkg) {
				packages[i]->old_package = spkg;
				packages[i]->name = &spool[spkg->name];
				packages[i]->old_version = &spool[spkg->version];
				bitarray_set(&trans->syspkgs, spkg - spkgs, 0);
			}
			if (!packages[i]->old_package) {
				packages[i]->name = strdup(packages[i]->name);
				packages[i]->state |= RAZOR_PACKAGE_UNAVAILABLE_FLAG;
				trans->errors++;
			}
		} else {
			if (upkg) {
				packages[i]->new_package = upkg;
				packages[i]->name = &upool[upkg->name];
				packages[i]->new_version = &upool[upkg->version];

				if (up->name != upkg->name) {
					packages[i]->dep_package = &upool[upkg->name];
					packages[i]->dep_type = up->type;
					packages[i]->dep_property = &upool[up->name];
					packages[i]->dep_relation = up->relation;
					packages[i]->dep_version = &upool[up->version];
				}

				if (spkg) {
					packages[i]->old_package = spkg;
					packages[i]->old_version = &spool[spkg->version];
					if (versioncmp(&spool[spkg->version], &upool[up->version]) >= 0) {
						packages[i]->state = RAZOR_PACKAGE_UP_TO_DATE;
						trans->errors++;
						continue;
					}
					bitarray_set(&trans->syspkgs, spkg - spkgs, 0);
				}
				bitarray_set(&trans->uppkgs, upkg - upkgs, 1);
			}
			if (!packages[i]->new_package) {
				packages[i]->name = strdup(packages[i]->name);
				packages[i]->state |= RAZOR_PACKAGE_UNAVAILABLE_FLAG;
				trans->errors++;
			}
		}
	}
}

static void
find_all_packages(struct razor_transaction_resolver *trans)
{
	struct razor_transaction_package *tp;
	struct razor_package *sp, *spkgs, *send, *up, *upkgs, *uend;
	const char *spool, *upool;

	spkgs = trans->system->packages.data;
	send = trans->system->packages.data + trans->system->packages.size;
	spool = trans->system->string_pool.data;
	up = upkgs = trans->upstream->packages.data;
	uend = trans->upstream->packages.data + trans->upstream->packages.size;
	upool = trans->upstream->string_pool.data;

	for (sp = spkgs; sp < send; sp++) {
		while (up < uend && strcmp(&spool[sp->name], &upool[up->name]) > 0)
			up++;
		if (strcmp(&spool[sp->name], &upool[up->name]) == 0) {
			tp = array_add(&trans->packages, sizeof *tp);
			memset(tp, 0, sizeof *tp);
			tp->old_package = sp;
			tp->new_package = up;
			tp->name = &upool[up->name];
			tp->old_version = &spool[sp->version];
			tp->new_version = &upool[up->version];
			tp->state = RAZOR_PACKAGE_INSTALL;
			bitarray_set(&trans->uppkgs, up - upkgs, 1);
			bitarray_set(&trans->syspkgs, sp - spkgs, 0);
		}
	}
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
find_package_for_file(struct razor_set *set, struct bitarray *pkgbits,
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
find_installed_package_for_file(struct razor_transaction_resolver *trans,
				const char *filename)
{
	struct razor_package *pkg;

	pkg = find_package_for_file(trans->system, &trans->syspkgs,
				    filename, 1);
	if (!pkg)
		pkg = find_package_for_file(trans->upstream, &trans->uppkgs,
					    filename, 1);
	return pkg;
}

static struct razor_package *
find_uninstalled_package_for_file(struct razor_transaction_resolver *trans,
				  const char *filename)
{
	struct razor_package *pkg;

	pkg = find_package_for_file(trans->upstream, &trans->uppkgs,
				    filename, 0);
	if (!pkg)
		pkg = find_package_for_file(trans->system, &trans->syspkgs,
					    filename, 0);
	return pkg;
}

static struct razor_property *
skip_to_matching_property(struct razor_transaction_resolver *trans,
			  struct razor_property *match,
			  struct razor_property *prop)
{
	struct razor_set *mset, *pset;
	const char *ppool, *mpool;
	struct razor_property *prop_end;

	if (property_in_set(match, trans->system))
		mset = trans->system;
	else
		mset = trans->upstream;

	if (property_in_set(prop, trans->system))
		pset = trans->system;
	else if (property_in_set(prop, trans->upstream))
		pset = trans->upstream;
	else
		return prop;

	prop_end = pset->properties.data + pset->properties.size;
	ppool = pset->string_pool.data;
	mpool = mset->string_pool.data;

	while (prop < prop_end &&
	       strcmp(&ppool[prop->name], &mpool[match->name]) < 0)
		prop++;
	return prop;
}

static struct razor_package *
find_package_matching(struct razor_transaction_resolver *trans, int installed,
		      struct razor_property *prop,
		      struct razor_property *req,
		      struct razor_set *req_set)
{
	struct razor_set *set;
	struct bitarray *pkgbits;
	struct razor_package *pkgs;
	struct razor_property *props, *prop_end;
	enum razor_property_type match_type;
	const char *pool;
	const char *rpool;
	int match_name = (req->type == RAZOR_PROPERTY_OBSOLETES);
	int match;

	if (property_in_set(prop, trans->system)) {
		set = trans->system;
		pkgbits = &trans->syspkgs;
	} else if (property_in_set(prop, trans->upstream)) {
		set = trans->upstream;
		pkgbits = &trans->uppkgs;
	} else
		return NULL;

	if (!req_set) {
		if (property_in_set(req, trans->system))
			req_set = trans->system;
		else
			req_set = trans->upstream;
	}
	rpool = req_set->string_pool.data;

	if (req->type == RAZOR_PROPERTY_PROVIDES)
		match_type = RAZOR_PROPERTY_CONFLICTS;
	else
		match_type = RAZOR_PROPERTY_PROVIDES;

	pkgs = set->packages.data;
	props = set->properties.data;
	prop_end = set->properties.data + set->properties.size;
	pool = set->string_pool.data;

	/* Find first matching property */
	while (prop < prop_end &&
	       strcmp(&pool[prop->name], &rpool[req->name]) < 0)
		prop++;
	if (prop == prop_end ||
	    strcmp(&pool[prop->name], &rpool[req->name]) > 0)
		return NULL;

	if (prop->type < match_type) {
		while (prop < prop_end && prop->type != match_type)
			prop++;
	} else {
		while (prop >= props && prop->type != match_type)
			prop--;
		while (prop > props + 1 && (prop - 1)->type == match_type)
			prop--;
	}

	/* Scan matching properties */
	while (prop < prop_end && prop->type == match_type &&
	       strcmp(&pool[prop->name], &rpool[req->name]) == 0) {
		if (match_type == RAZOR_PROPERTY_PROVIDES)
			match = provider_satisfies_requirement(prop, pool, req, rpool);
		else
			match = provider_satisfies_requirement(req, rpool, prop, pool);
		if (match) {
			struct list *pkg;

			for (pkg = list_first(&prop->packages, &set->package_pool); pkg; pkg = list_next(pkg)) {
				if (bitarray_get(pkgbits, pkg->data) != installed)
					continue;
				if (!match_name ||
				    strcmp(&pool[pkgs[pkg->data].name],
					   &rpool[req->name]) == 0)
					return &pkgs[pkg->data];
			}
		}
		prop++;
	}

	return NULL;
}

static struct razor_package *
find_installed_package_for_property(struct razor_transaction_resolver *trans,
				    struct razor_property *sys_start,
				    struct razor_property *up_start,
				    struct razor_property *req)
{
	struct razor_package *pkg;

	pkg = find_package_matching(trans, 1, sys_start, req, NULL);
	if (!pkg)
		pkg = find_package_matching(trans, 1, up_start, req, NULL);
	return pkg;
}

static struct razor_package *
find_uninstalled_package_for_property(struct razor_transaction_resolver *trans,
				      struct razor_property *sys_start,
				      struct razor_property *up_start,
				      struct razor_property *req)
{
	struct razor_package *pkg;

	pkg = find_package_matching(trans, 0, up_start, req, NULL);
	if (!pkg)
		pkg = find_package_matching(trans, 0, sys_start, req, NULL);
	return pkg;
}

static struct razor_transaction_package *
find_transaction_package(struct razor_transaction_resolver *trans,
			 const char *name)
{
	struct razor_transaction_package *packages;
	int count, i;

	packages = trans->packages.data;
	count = trans->packages.size / sizeof *packages;
	for (i = 0; i < count; i++) {
		if (packages[i].name && !strcmp(packages[i].name, name))
			return &packages[i];
	}
	return NULL;
}

/* FIXME? */
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

static int
prop_is_being_removed(struct razor_transaction_resolver *trans,
		      struct razor_property *prop)
{
	struct list *pkg;

	for (pkg = list_first(&prop->packages, &trans->system->package_pool); pkg; pkg = list_next(pkg)) {
		if (bitarray_get(&trans->syspkgs, pkg->data))
			return 0;
	}
	return 1;
}

static int
prop_is_being_updated(struct razor_transaction_resolver *trans,
		      struct razor_property *prop)
{
	struct razor_package *packages = trans->system->packages.data;
	const char *pool = trans->system->string_pool.data;
	struct razor_transaction_package *tp;
	struct list *pkg;

	/* Assumes prop_is_being_removed returns true */

	for (pkg = list_first(&prop->packages, &trans->system->package_pool); pkg; pkg = list_next(pkg)) {
		tp = find_transaction_package(trans, &pool[packages[pkg->data].name]);
		if (tp && tp->state == RAZOR_PACKAGE_REMOVE)
			return 0;
	}
	return 1;
}

static void
add_transaction_package(struct razor_transaction_resolver *trans,
			struct razor_package *new_package,
			struct razor_package *old_package,
			enum razor_transaction_package_state state,
			const char *req_package,
			struct razor_property *req_prop)
{
	struct razor_set *new_package_set, *old_package_set, *req_set;
	struct bitarray *reqpkgbits;
	struct razor_transaction_package *tp, *already;
	const char *pool;
	struct razor_package *pkgs;
	struct list *pkg;
	int contradiction = 0;

	if (package_in_set(new_package, trans->system))
		new_package_set = trans->system;
	else
		new_package_set = trans->upstream;
	if (package_in_set(old_package, trans->system))
		old_package_set = trans->system;
	else
		old_package_set = trans->upstream;
	if (property_in_set(req_prop, trans->system)) {
		req_set = trans->system;
		reqpkgbits = &trans->syspkgs;
	} else {
		req_set = trans->upstream;
		reqpkgbits = &trans->uppkgs;
	}

	if (new_package) {
		pool = new_package_set->string_pool.data;
		already = find_transaction_package(trans, &pool[new_package->name]);
		if (already) {
			if (already->new_package == new_package) {
				/* Already taken care of */
				return;
			} else if (new_package_set == trans->upstream &&
				   already->state == RAZOR_PACKAGE_FORCED_UPDATE) {
				already->new_package = new_package;
				return;
			}

			/* Oops. We lose */
			if (state != RAZOR_PACKAGE_CONTRADICTION)
				contradiction = 1;
		}
	} else if (old_package) {
		pool = old_package_set->string_pool.data;
		already = find_transaction_package(trans, &pool[old_package->name]);
		if (already) {
			if (already->old_package == old_package) {
				/* Already taken care of */
				return;
			} else if (old_package_set == trans->system) {
				already->old_package = old_package;
				return;
			}

			/* Oops. We lose */
			if (state != RAZOR_PACKAGE_CONTRADICTION)
				contradiction = 1;
		}
	} else
		state = RAZOR_PACKAGE_UNSATISFIABLE;

	tp = array_add(&trans->packages, sizeof *tp);
	memset(tp, 0, sizeof *tp);

	if (new_package) {
		pool = new_package_set->string_pool.data;
		tp->new_package = new_package;
		tp->name = &pool[new_package->name];
		tp->new_version = &pool[new_package->version];

		pkgs = new_package_set->packages.data;
	}
	if (old_package) {
		pool = old_package_set->string_pool.data;
		tp->old_package = old_package;
		tp->name = &pool[old_package->name];
		tp->old_version = &pool[old_package->version];

		pkgs = old_package_set->packages.data;
	}

	tp->state = state;
	if (state != RAZOR_PACKAGE_INSTALL &&
	    state != RAZOR_PACKAGE_FORCED_UPDATE &&
	    state != RAZOR_PACKAGE_REMOVE &&
	    state != RAZOR_PACKAGE_OBSOLETED)
		trans->errors++;

	if (contradiction) {
		/* Do this now, after adding tp, so that it ends up
		 * after both the INSTALL and the REMOVE in the array.
		 */
		add_transaction_package(trans, new_package, old_package,
					RAZOR_PACKAGE_CONTRADICTION,
					NULL, NULL);
	}

	if (req_package)
		tp->dep_package = req_package;
	if (!req_prop)
		return;

	pool = req_set->string_pool.data;
	pkgs = req_set->packages.data;
	if (!req_package) {
		for (pkg = list_first(&req_prop->packages, &req_set->package_pool); pkg; pkg = list_next(pkg)) {
			if (bitarray_get(reqpkgbits, pkg->data))
				break;
		}
		if (pkg)
			tp->dep_package = &pool[pkgs[pkg->data].name];
	}

	tp->dep_type = req_prop->type;
	tp->dep_property = &pool[req_prop->name];
	tp->dep_relation = req_prop->relation;
	tp->dep_version = &pool[req_prop->version];
}

static void
razor_transaction_satisfy(struct razor_transaction_resolver *trans)
{
	struct razor_package *spkgs, *upkgs, *pkg;
	struct razor_property *sp, *sprops, *sprop_end;
	struct razor_property *up, *uprops, *uprop_end;
	struct razor_property *sr, *ur, *first_up;
	const char *spool, *upool, *removed_package;
	struct list *reqpkg;

	spkgs = trans->system->packages.data;
	sprops = trans->system->properties.data;
	sprop_end = trans->system->properties.data + trans->system->properties.size;
	spool = trans->system->string_pool.data;
	upkgs = trans->upstream->packages.data;
	uprops = trans->upstream->properties.data;
	uprop_end = trans->upstream->properties.data + trans->upstream->properties.size;
	upool = trans->upstream->string_pool.data;

	sp = sprops;
	for (up = uprops; up < uprop_end; up++) {
		/* Skip 'up' ahead to a property of a package which is
		 * to-be-installed.
		 */
		while (up < uprop_end &&
		       !prop_is_being_installed(trans, up))
			up++;
		if (up == uprop_end)
			break;
		sp = skip_to_matching_property(trans, up, sp);

		switch (up->type) {
		case RAZOR_PROPERTY_REQUIRES:
			if (!strncmp(&upool[up->name], "rpmlib(", 7))
				break;

			if (find_installed_package_for_property(trans, sp, up, up) ||
			    find_installed_package_for_file(trans, &upool[up->name])) {
				/* Requires something that is either installed
				 * or to-be-installed.
				 */
				break;
			}

			/* See if we can install a new upstream provider */
			pkg = find_uninstalled_package_for_property(trans, sp, up, up);
			if (!pkg)
				pkg = find_uninstalled_package_for_file(trans, &upool[up->name]);
			add_transaction_package(trans, pkg, NULL,
						RAZOR_PACKAGE_INSTALL,
						NULL, up);
			break;

		case RAZOR_PROPERTY_PROVIDES:
			/* find_installed_package_for_property works backwards
			 * here, finding a *conflicting* installed package.
			 */
			pkg = find_installed_package_for_property(trans, sp, up, up);
			if (!pkg)
				break;

			if (package_in_set(pkg, trans->system)) {
				/* pkg CONFLICTS with what 'up' PROVIDES. Try
				 * finding an upgrade
				 */
				add_transaction_package(trans, NULL, pkg,
							RAZOR_PACKAGE_FORCED_UPDATE,
							&upool[up->name], sp);
			} else {
				add_transaction_package(trans, NULL, pkg,
							RAZOR_PACKAGE_CONTRADICTION,
							NULL, up);
			}
			break;

		case RAZOR_PROPERTY_CONFLICTS:
			pkg = find_installed_package_for_property(trans, sp, up, up);
			if (!pkg)
				break;

			if (package_in_set(pkg, trans->system)) {
				/* Conflicts with something already installed.
				 * Try to upgrade out.
				 */
				add_transaction_package(trans, NULL, pkg,
							RAZOR_PACKAGE_FORCED_UPDATE,
							NULL, up);
			} else {
				add_transaction_package(trans, pkg, NULL,
							RAZOR_PACKAGE_CONTRADICTION,
							NULL, up);
			}
			break;

		case RAZOR_PROPERTY_OBSOLETES:
			pkg = find_installed_package_for_property(trans, sp, up, up);
			if (pkg) {
				/* If pkg is to-be-installed, this
				 * will add a CONTRADICTION error as well.
				 */
				add_transaction_package(trans, NULL, pkg,
							RAZOR_PACKAGE_OBSOLETED,
							NULL, up);
			}
			break;

		default:
			/* can't happen */
			break;
		}
	}

	up = uprops;
	for (sp = sprops; sp < sprop_end; sp++) {
		/* Skip 'sp' ahead to a PROVIDES of a package which is
		 * to-be-removed.
		 */
		while (sp < sprop_end &&
		       (sp->type != RAZOR_PROPERTY_PROVIDES ||
			!prop_is_being_removed(trans, sp)))
			sp++;
		if (sp == sprop_end)
			break;

		removed_package = &spool[spkgs[list_first(&sp->packages, &trans->system->package_pool)->data].name];

		/* Skip 'up' to match */
		up = skip_to_matching_property(trans, sp, up);
		ur = first_up = up;

		/* If the package is just being upgraded, we may
		 * already be installing an identical PROVIDES, so
		 * check for that.
		 */
		while (up < uprop_end &&
		       strcmp(&spool[sp->name], &upool[up->name]) == 0 &&
		       (up->type != RAZOR_PROPERTY_PROVIDES || 
			sp->relation != up->relation ||
			strcmp(&spool[sp->name], &upool[up->name]) != 0))
			up++;
		if (up < uprop_end &&
		    up->type == RAZOR_PROPERTY_PROVIDES &&
		    strcmp(&spool[sp->name], &upool[up->name]) == 0 &&
		    sp->relation == up->relation &&
		    strcmp(&spool[sp->version], &upool[up->version]) == 0 &&
		    prop_is_being_installed(trans, up)) {
			up = first_up;
			continue;
		}
		up = first_up;

		/* For all still-installed packages that require
		 * sp->name, see if they are satisfied by any other
		 * still-installed or to-be-installed property. If
		 * not, either remove or attempt to update the
		 * package, depending on why the required property has
		 * disappeared
		 */
		sr = sp;
		while (sr > sprops + 1 && (sr - 1)->name == sr->name)
			sr--;
		for (; sr->type == RAZOR_PROPERTY_REQUIRES; sr++) {
			if (prop_is_being_removed(trans, sr))
				continue;
			if (find_installed_package_for_property(trans, sp, up, sr))
				continue;

			for (reqpkg = list_first(&sr->packages, &trans->system->package_pool); reqpkg; reqpkg = list_next(reqpkg)) {
				if (!bitarray_get(&trans->syspkgs, reqpkg->data))
					continue;
				pkg = &spkgs[reqpkg->data];
				if (prop_is_being_updated(trans, sp)) {
					add_transaction_package(trans, NULL, pkg,
								RAZOR_PACKAGE_FORCED_UPDATE,
								removed_package, NULL);
				} else {
					add_transaction_package(trans, NULL, pkg,
								RAZOR_PACKAGE_REMOVE,
								removed_package, sr);
				}
			}
		}
	}
}

struct razor_transaction *
razor_transaction_create(struct razor_set *system, struct razor_set *upstream,
			 int update_count, const char **update_packages,
			 int remove_count, const char **remove_packages)
{
	struct razor_transaction_resolver trans;
	struct razor_transaction *ret_trans;
	struct razor_transaction_package *tp;
	int start, end, i;

	trans.system = system;
	trans.upstream = upstream ? upstream : razor_set_create();
	array_init(&trans.packages);
	bitarray_init(&trans.syspkgs, trans.system->packages.size / sizeof (struct razor_package), 1);
	bitarray_init(&trans.uppkgs, trans.upstream->packages.size / sizeof (struct razor_package), 0);
	trans.errors = 0;

	if (update_count > 0 || remove_count > 0) {
		for (i = 0; i < update_count; i++) {
			tp = array_add(&trans.packages, sizeof *tp);
			memset(tp, 0, sizeof *tp);
			tp->name = update_packages[i];
			tp->state = RAZOR_PACKAGE_INSTALL;
		}
		for (i = 0; i < remove_count; i++) {
			tp = array_add(&trans.packages, sizeof *tp);
			memset(tp, 0, sizeof *tp);
			tp->name = remove_packages[i];
			tp->state = RAZOR_PACKAGE_REMOVE;
		}
	} else
		find_all_packages(&trans);

	start = 0;
	end = trans.packages.size / sizeof (struct razor_transaction_package);

	while (start != end) {
		resolve_new_packages(&trans, start, end);
		if (trans.errors)
			break;

		razor_transaction_satisfy(&trans);

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

static void
print_requirement(struct razor_transaction_package *p)
{
	if (p->dep_type == RAZOR_PROPERTY_CONFLICTS &&
	    !strcmp(p->dep_package, p->name)) {
		printf(" because %s %s conflicts with %s",
		       p->name, p->old_version, p->dep_property);
		if (*p->dep_version) {
			printf(" %s %s",
			       razor_version_relations[p->dep_relation],
			       p->dep_version);
		}
	} else {
		if (strcmp(p->name, p->dep_package) != 0)
			printf(" for %s", p->dep_package);
		if (*p->dep_version) {
			printf(", which %s %s %s %s",
			       razor_property_types[p->dep_type],
			       p->dep_property,
			       razor_version_relations[p->dep_relation],
			       p->dep_version);
		} else if (strcmp(p->dep_property, p->name) != 0) {
			printf(", which %s %s",
			       razor_property_types[p->dep_type],
			       p->dep_property);
		}
	}
}

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

			printf("Installing %s %s", p->name, p->new_version);
			if (p->dep_package)
				print_requirement(p);
			printf("\n");
			break;

		case RAZOR_PACKAGE_FORCED_UPDATE:
			if (errors_only)
				break;

			printf("Updating %s to %s due to update of %s\n",
			       p->name, p->new_version, p->dep_package);
			break;

		case RAZOR_PACKAGE_REMOVE:
			if (errors_only)
				break;
			printf("Removing %s %s", p->name, p->old_version);
			if (p->dep_package) {
				printf(" which required %s",
				       p->dep_package);
				if (strcmp(p->dep_property, p->dep_package) != 0)
					printf(" for %s", p->dep_property);
			}
			printf("\n");
			break;

		case RAZOR_PACKAGE_OBSOLETED:
			if (errors_only)
				break;
			printf("Removing %s %s", p->name, p->old_version);
			if (p->dep_package) {
				printf(" which is obsoleted by %s",
				       p->dep_package);
			}
			printf("\n");
			break;

		case RAZOR_PACKAGE_INSTALL_UNAVAILABLE:
			printf("Error: can't find %s", p->name);
			if (p->dep_package) {
				printf(" (which is required");
				print_requirement(p);
				printf(")");
			}
			printf("\n");
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_UPDATE_UNAVAILABLE:
			printf("Error: can't find an updated version of %s (which must be updated due to update of %s)\n",
			       p->name, p->dep_package);
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_REMOVE_NOT_INSTALLED:
			printf("Error: can't remove %s: not installed\n", p->name);
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_UP_TO_DATE:
			printf("Error: can't update %s", p->name);
			if (p->dep_package)
				printf(" (which must be updated due to update of %s)", p->dep_package);
			printf(": %s is most recent version\n", p->old_version);
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_CONTRADICTION:
			printf("Error: package %s is marked for both installation and removal\n", p->name);
			errors_only = 1;
			break;

		case RAZOR_PACKAGE_OLD_CONFLICT:
			printf("Error: can't install %s, because installed package %s conflicts with ",
			       p->name, p->dep_package);
			if (*p->dep_version) {
				printf("%s %s %s",
				       p->dep_property,
				       razor_version_relations[p->dep_relation],
				       p->dep_version);
			} else
				printf("it");
			printf("\n");

			errors_only = 1;
			break;

		case RAZOR_PACKAGE_NEW_CONFLICT:
			printf("Error: can't install %s, because it conflicts with %s",
			       p->name, p->dep_package);
			if (*p->dep_version) {
				printf(" %s %s",
				       razor_version_relations[p->dep_relation],
				       p->dep_version);
			}
			printf("\n");

			errors_only = 1;
			break;

		case RAZOR_PACKAGE_UNSATISFIABLE:
			printf("Error: can't find package for %s", p->dep_property);
			if (*p->dep_version) {
				printf(" %s %s",
					razor_version_relations[p->dep_relation],
					p->dep_version);
			}
			printf(" which is required by %s\n",
				p->dep_package);
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
		if (trans->packages[p].new_package) {
			pkg = array_add(&install_packages, sizeof *pkg);
			*pkg = *trans->packages[p].new_package;
		} else {
			pkg = array_add(&remove_packages, sizeof *pkg);
			*pkg = *trans->packages[p].old_package;
		}
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
		if (!trans->packages[p].dep_package &&
		    (trans->packages[p].state == RAZOR_PACKAGE_INSTALL_UNAVAILABLE ||
		     trans->packages[p].state == RAZOR_PACKAGE_REMOVE_NOT_INSTALLED))
			free((char *)trans->packages[p].name);
	}
	free(trans);

	/* FIXME: free upstream if it was created as an empty set */
}
