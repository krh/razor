#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <rpm/rpmlib.h>

#include "razor.h"

#define	RPM_LEAD_SIZE 96

struct rpm_lead {
	unsigned char magic[4];
	unsigned char major;
	unsigned char minor;
	short type;
	short archnum;
	char name[66];
	short osnum;
	short signature_type;
	char reserved[16];
};

struct rpm_header {
	unsigned char magic[4];
	unsigned char reserved[4];
	int nindex;
	int hsize;
};

struct rpm_header_index {
	int tag;
	int type;
	int offset;
	int count;
};

struct properties {
	struct rpm_header_index *name;
	struct rpm_header_index *version;
	struct rpm_header_index *flags;
};

struct rpm {
	struct rpm_header *signature;
	struct rpm_header *header;

	struct rpm_header_index *name;
	struct rpm_header_index *version;
	struct rpm_header_index *release;

	struct rpm_header_index *dirnames;
	struct rpm_header_index *dirindexes;
	struct rpm_header_index *basenames;

	struct properties provides;
	struct properties requires;
	struct properties obsoletes;
	struct properties conflicts;

	const char *pool;
	void *map;
	size_t size;
};

#define ALIGN(value, base) (((value) + (base - 1)) & ~((base) - 1))

static void
import_properties(struct razor_importer *importer,
		  struct properties *properties,
		  const char *pool, unsigned long type)
{
	const char *name, *version;
	int i, count;

	/* assert: count is the same for all arrays */

	if (properties->name == NULL)
		return;

	count = ntohl(properties->name->count);
	name = pool + ntohl(properties->name->offset);
	version = pool + ntohl(properties->version->offset);
	for (i = 0; i < count; i++) {
		razor_importer_add_property(importer, name, version, type);
		name += strlen(name) + 1;
		version += strlen(version) + 1;
	}
}

static void
import_files(struct razor_importer *importer, struct rpm *rpm)
{
	const char *name, **dir;
	unsigned long *index;
	int i, count;
	char buffer[256];

	/* assert: count is the same for all arrays */

	if (rpm->dirnames == NULL)
		return;

	count = ntohl(rpm->dirnames->count);
	dir = calloc(count, sizeof *dir);
	name = rpm->pool + ntohl(rpm->dirnames->offset);
	for (i = 0; i < count; i++) {
		dir[i] = name;
		name += strlen(name) + 1;
	}

	count = ntohl(rpm->basenames->count);
	index = (unsigned long *) (rpm->pool + ntohl(rpm->dirindexes->offset));
	name = rpm->pool + ntohl(rpm->basenames->offset);
	for (i = 0; i < count; i++) {
		snprintf(buffer, sizeof buffer,
			 "%s%s", dir[ntohl(*index)], name);
		razor_importer_add_file(importer, buffer);
		name += strlen(name) + 1;
		index++;
	}
}

static int
razor_rpm_open(struct rpm *rpm, const char *filename)
{
	struct rpm_header_index *base, *index;
	struct stat buf;
	int fd, nindex, hsize, i;

	memset(rpm, 0, sizeof *rpm);
	if (stat(filename, &buf) < 0) {
		fprintf(stderr, "no such file %s (%m)\n", filename);
		return -1;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "couldn't open %s\n", filename);
		return -1;
	}
	rpm->size = buf.st_size;
	rpm->map = mmap(NULL, rpm->size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (rpm->map == MAP_FAILED) {
		fprintf(stderr, "couldn't mmap %s\n", filename);
		return -1;
	}
	close(fd);

	rpm->signature = rpm->map + RPM_LEAD_SIZE;
	nindex = ntohl(rpm->signature->nindex);
	hsize = ntohl(rpm->signature->hsize);
	rpm->header = (void *) (rpm->signature + 1) +
		ALIGN(nindex * sizeof *index + hsize, 8);

	nindex = ntohl(rpm->header->nindex);
	base = (struct rpm_header_index *) (rpm->header + 1);
	rpm->pool = (void *) base + nindex * sizeof *index;

	for (i = 0; i < nindex; i++) {
		index = base + i;
		switch (ntohl(index->tag)) {
		case RPMTAG_NAME:
			rpm->name = index;
			break;
		case RPMTAG_VERSION:
			rpm->version = index;
			break;
		case RPMTAG_RELEASE:
			rpm->release = index;
			break;

		case RPMTAG_REQUIRENAME:
			rpm->requires.name = index;
			break;
		case RPMTAG_REQUIREVERSION:
			rpm->requires.version = index;
			break;
		case RPMTAG_REQUIREFLAGS:
			rpm->requires.flags = index;
			break;

		case RPMTAG_PROVIDENAME:
			rpm->provides.name = index;
			break;
		case RPMTAG_PROVIDEVERSION:
			rpm->provides.version = index;
			break;
		case RPMTAG_PROVIDEFLAGS:
			rpm->provides.flags = index;
			break;

		case RPMTAG_OBSOLETENAME:
			rpm->obsoletes.name = index;
			break;
		case RPMTAG_OBSOLETEVERSION:
			rpm->obsoletes.version = index;
			break;
		case RPMTAG_OBSOLETEFLAGS:
			rpm->obsoletes.flags = index;
			break;

		case RPMTAG_CONFLICTNAME:
			rpm->conflicts.name = index;
			break;
		case RPMTAG_CONFLICTVERSION:
			rpm->conflicts.version = index;
			break;
		case RPMTAG_CONFLICTFLAGS:
			rpm->conflicts.flags = index;
			break;

		case RPMTAG_DIRINDEXES:
			rpm->dirindexes = index;
			break;
		case RPMTAG_BASENAMES:
			rpm->basenames = index;
			break;
		case RPMTAG_DIRNAMES:
			rpm->dirnames = index;
			break;
		}
	}

	return 0;
}

static int
razor_rpm_close(struct rpm *rpm)
{
	return munmap(rpm->map, rpm->size);
}

int
razor_importer_add_rpm(struct razor_importer *importer, const char *filename)
{
	struct rpm rpm;

	if (razor_rpm_open(&rpm, filename) < 0) {
		fprintf(stderr, "failed to open rpm %s (%m)\n", filename);
		return -1;
	}

	razor_importer_begin_package(importer,
				     rpm.pool + ntohl(rpm.name->offset),
				     rpm.pool + ntohl(rpm.version->offset));

	import_properties(importer, &rpm.requires,
			  rpm.pool, RAZOR_PROPERTY_REQUIRES);
	import_properties(importer, &rpm.provides,
			  rpm.pool, RAZOR_PROPERTY_PROVIDES);
	import_properties(importer, &rpm.conflicts,
			  rpm.pool, RAZOR_PROPERTY_CONFLICTS);
	import_properties(importer, &rpm.obsoletes,
			  rpm.pool, RAZOR_PROPERTY_OBSOLETES);
	import_files(importer, &rpm);

	razor_importer_finish_package(importer);

	razor_rpm_close(&rpm);

	return 0;
}
