#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <rpm/rpmlib.h>
#include <zlib.h>

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

struct razor_rpm {
	struct rpm_header *signature;
	struct rpm_header *header;

	struct rpm_header_index *name;
	struct rpm_header_index *version;
	struct rpm_header_index *release;

	struct rpm_header_index *dirnames;
	struct rpm_header_index *dirindexes;
	struct rpm_header_index *basenames;
	struct rpm_header_index *filesizes;
	struct rpm_header_index *filemodes;
	struct rpm_header_index *filestates;
	const char **dirs;

	struct properties provides;
	struct properties requires;
	struct properties obsoletes;
	struct properties conflicts;

	const char *pool;
	void *map;
	size_t size;
	void *payload;
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
import_files(struct razor_importer *importer, struct razor_rpm *rpm)
{
	const char *name;
	unsigned long *index;
	int i, count;
	char buffer[256];

	/* assert: count is the same for all arrays */

	if (rpm->dirnames == NULL)
		return;

	count = ntohl(rpm->basenames->count);
	index = (unsigned long *) (rpm->pool + ntohl(rpm->dirindexes->offset));
	name = rpm->pool + ntohl(rpm->basenames->offset);
	for (i = 0; i < count; i++) {
		snprintf(buffer, sizeof buffer,
			 "%s%s", rpm->dirs[ntohl(*index)], name);
		razor_importer_add_file(importer, buffer);
		name += strlen(name) + 1;
		index++;
	}
}

#define MAP_ENTRY(field, tag) { offsetof(struct razor_rpm, field), tag }

static struct index_map {
	unsigned int offset;
	unsigned int tag;
} index_map[] =	{
	MAP_ENTRY(name, RPMTAG_NAME),
	MAP_ENTRY(version, RPMTAG_VERSION),
	MAP_ENTRY(release, RPMTAG_RELEASE),
	MAP_ENTRY(requires.name, RPMTAG_REQUIRENAME),
	MAP_ENTRY(requires.version, RPMTAG_REQUIREVERSION),
	MAP_ENTRY(requires.flags, RPMTAG_REQUIREFLAGS),
	MAP_ENTRY(provides.name, RPMTAG_PROVIDENAME),
	MAP_ENTRY(provides.version, RPMTAG_PROVIDEVERSION),
	MAP_ENTRY(provides.flags, RPMTAG_PROVIDEFLAGS),
	MAP_ENTRY(obsoletes.name, RPMTAG_OBSOLETENAME),
	MAP_ENTRY(obsoletes.version, RPMTAG_OBSOLETEVERSION),
	MAP_ENTRY(obsoletes.flags, RPMTAG_OBSOLETEFLAGS),
	MAP_ENTRY(conflicts.name, RPMTAG_CONFLICTNAME),
	MAP_ENTRY(conflicts.version, RPMTAG_CONFLICTVERSION),
	MAP_ENTRY(conflicts.flags, RPMTAG_CONFLICTFLAGS),
	MAP_ENTRY(dirindexes, RPMTAG_DIRINDEXES),
	MAP_ENTRY(basenames, RPMTAG_BASENAMES),
	MAP_ENTRY(dirnames, RPMTAG_DIRNAMES),
	MAP_ENTRY(filesizes, RPMTAG_FILESIZES),
	MAP_ENTRY(filemodes, RPMTAG_FILEMODES),
	MAP_ENTRY(filestates, RPMTAG_FILESTATES),
};

static struct rpm_header_index *
razor_rpm_get_header(struct razor_rpm *rpm, unsigned int tag)
{
	struct rpm_header_index *index, *end;

	index = (struct rpm_header_index *) (rpm->header + 1);
	end = index + ntohl(rpm->header->nindex);
	while (index < end) {
		if (ntohl(index->tag) == tag)
			return index;
		index++;
	}

	return NULL;
}

struct razor_rpm *
razor_rpm_open(const char *filename)
{
	struct razor_rpm *rpm;
	struct rpm_header_index *base, *index;
	struct stat buf;
	int fd, nindex, hsize, i, j, count;
	const char *name;

	rpm = malloc(sizeof *rpm);
	memset(rpm, 0, sizeof *rpm);
	if (stat(filename, &buf) < 0) {
		fprintf(stderr, "no such file %s (%m)\n", filename);
		return NULL;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "couldn't open %s\n", filename);
		return NULL;
	}
	rpm->size = buf.st_size;
	rpm->map = mmap(NULL, rpm->size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (rpm->map == MAP_FAILED) {
		fprintf(stderr, "couldn't mmap %s\n", filename);
		return NULL;
	}
	close(fd);

	rpm->signature = rpm->map + RPM_LEAD_SIZE;
	nindex = ntohl(rpm->signature->nindex);
	hsize = ntohl(rpm->signature->hsize);
	rpm->header = (void *) (rpm->signature + 1) +
		ALIGN(nindex * sizeof *index + hsize, 8);
	nindex = ntohl(rpm->header->nindex);
	hsize = ntohl(rpm->header->hsize);
	rpm->payload = (void *) (rpm->header + 1) +
		nindex * sizeof *index + hsize;

	base = (struct rpm_header_index *) (rpm->header + 1);
	rpm->pool = (void *) base + nindex * sizeof *index;

	for (i = 0; i < nindex; i++) {
		index = base + i;
		for (j = 0; j < ARRAY_SIZE(index_map); j++) {
			struct rpm_header_index **p;
			if (index_map[j].tag == ntohl(index->tag)) {
				p = (void *) rpm + index_map[j].offset;
				*p = index;
			}
		}				 
	}

	/* Look up dir names now so we can index them directly. */
	if (rpm->dirnames != NULL) {
		count = ntohl(rpm->dirnames->count);
		rpm->dirs = calloc(count, sizeof *rpm->dirs);
		name = rpm->pool + ntohl(rpm->dirnames->offset);
		for (i = 0; i < count; i++) {
			rpm->dirs[i] = name;
			name += strlen(name) + 1;
		}
	}

	return rpm;
}

struct cpio_file_header {
	char magic[6];
	char inode[8];
	char mode[8];
	char uid[8];
	char gid[8];
	char nlink[8];
	char mtime[8];
	char filesize[8];
	char devmajor[8];
	char devminor[8];
	char rdevmajor[8];
	char rdevminor[8];
	char namesize[8];
	char checksum[8];
	char filename[0];
};

/* gzip flags */
#define ASCII_FLAG   0x01 /* bit 0 set: file probably ascii text */
#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */

static int
create_path(const char *root, const char *path,
	    const char *name, unsigned mode, int *fd)
{
	char buffer[256], *p;
	const char *slash, *next;
	struct stat buf;

	/* Create all sub-directories in dir and then create name. We
	 * know root exists and is a dir, root does not end in a '/',
	 * and path has a leading '/'. */

	strcpy(buffer, root);
	p = buffer + strlen(buffer);
	slash = path;
	for (slash = path; slash[1] != '\0'; slash = next) {
		next = strchr(slash + 1, '/');
		memcpy(p, slash, next - slash);
		p += next - slash;
		*p = '\0';

		if (stat(buffer, &buf) == 0) {
			if (!S_ISDIR(buf.st_mode)) {
				fprintf(stderr,
					"%s exists but is not a directory\n",
					buffer);
				return -1;
			}
		} else if (mkdir(buffer, 0777) < 0) {
			fprintf(stderr, "failed to make directory %s: %m\n",
				buffer);
			return -1;
		}
		/* FIXME: permissions */
	}

	*p++ = '/';
	strcpy(p, name);

	switch (mode >> 12) {
	case REG:
	default:
		*fd = open(buffer, O_WRONLY | O_CREAT | O_TRUNC, mode & 0x1ff);
		return *fd;
	case XDIR:
		*fd = -1;
		return mkdir(buffer, mode & 0x1ff);
	}
}

static int
run_script(struct razor_rpm *rpm, const char *root, unsigned int tag)
{
	struct rpm_header_index *index;
	int pid, status, fd[2];
	const char *script;

	index = razor_rpm_get_header(rpm, tag);
	if (index == NULL) {
		fprintf(stderr, "no script for tag %d\n", tag);
		return 0;
	}

	if (pipe(fd) < 0) {
		fprintf(stderr, "failed to create pipe\n");
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "failed to fork, %m\n");
	} else if (pid == 0) {
		if (dup2(fd[0], STDIN_FILENO) < 0) {
			fprintf(stderr, "failed redirect stdin, %m\n");
			return -1;
		}
		if (close(fd[0]) < 0 || close(fd[1]) < 0) {
			fprintf(stderr, "failed to close pipe, %m\n");
			exit(-1);
		}
		if (chroot(root) < 0) {
			fprintf(stderr, "failed to chroot to %s, %m\n", root);
			return -1;
		}
		printf("executing script for %d\n", tag);
		if (execl("/bin/sh", "/bin/sh", NULL)) {
			fprintf(stderr, "failed to exec /bin/sh, %m\n");
			return -1;
		}
	} else {
		script = rpm->pool + ntohl(index->offset);
		if (write(fd[1], script, strlen(script)) < 0) {
			fprintf(stderr, "failed to pipe script, %m\n");
			return -1;
		}
		if (close(fd[0]) || close(fd[1])) {
			fprintf(stderr, "failed to close pipe, %m\n");
			return -1;
		}
		if (wait(&status) < 0) {
			fprintf(stderr, "wait for child failed, %m");
			return -1;
		}
		printf("script exited with status %d\n", status);
	}

	return 0;
}

int
razor_rpm_install(struct razor_rpm *rpm, const char *root)
{
	z_stream stream;
	unsigned char payload[32768], *gz_header;
	char buffer[256];
	int err, method, flags, count, i, fd, written;
	struct cpio_file_header *header;
	unsigned long *size, *index, rest, length;
	unsigned short *mode;
	const char *name, *dir;
	struct stat buf;

	if (stat(root, &buf) < 0 || !S_ISDIR(buf.st_mode)) {
		fprintf(stderr,
			"root installation directory \"%s\" does not exist\n",
			root);
		return -1;
	}

	gz_header = rpm->payload;
	if (gz_header[0] != 0x1f || gz_header[1] != 0x8b) {
		fprintf(stderr, "payload section doesn't have gz header\n");
		return -1;
	}

	method = gz_header[2];
	flags = gz_header[3];

	if (method != Z_DEFLATED || flags != 0) {
		fprintf(stderr,
			"unknown payload compression method or flags set\n");
		return -1;
	}

	run_script(rpm, root, RPMTAG_PREIN);

	stream.zalloc = NULL;
	stream.zfree = NULL;
	stream.opaque = NULL;

	stream.next_in  = gz_header + 10;
	stream.avail_in = (rpm->map + rpm->size) - (void *) stream.next_in;
	stream.next_out = NULL;
	stream.avail_out = 0;

	err = inflateInit2(&stream, -MAX_WBITS);
	if (err != Z_OK) {
		fprintf(stderr, "inflateInit error: %d\n", err);
		return -1;
	}

	count = ntohl(rpm->basenames->count);
	size = (unsigned long *) (rpm->pool + ntohl(rpm->filesizes->offset));
	index = (unsigned long *) (rpm->pool + ntohl(rpm->dirindexes->offset));
	mode = (unsigned short *) (rpm->pool + ntohl(rpm->filemodes->offset));
	name = rpm->pool + ntohl(rpm->basenames->offset);
	for (i = 0; i < count; i++) {
		dir = rpm->dirs[ntohl(*index)];
		snprintf(buffer, sizeof buffer, "%s%s", dir, name);

		stream.next_out = payload;
		/* Plus two for the leading '.' and the terminating NUL. */
		stream.avail_out =
			ALIGN(sizeof *header + strlen(buffer) + 2, 4);
		err = inflate(&stream, Z_SYNC_FLUSH);
		if (err != Z_OK) {
			fprintf(stderr, "inflate error: %d\n", err);
			return -1;
		}
	    
		header = (struct cpio_file_header *) payload;

		/* FIXME: Figure out if it's a symlink, device file,
		 * directorys or whatever.  Maybe do this upfront. */
		if (create_path(root, dir, name, ntohs(*mode), &fd) < 0)
			return -1;
		if (ntohs(*mode) >> 12 == XDIR)
			rest = 0;
		else
			rest = ntohl(*size);

		while (rest > 0) {
			if (ALIGN(rest, 4) > sizeof payload)
				length = sizeof payload;
			else
				length = rest;
			stream.next_out = payload;
			stream.avail_out = ALIGN(length, 4);
			err = inflate(&stream, Z_SYNC_FLUSH);
			if (err != Z_OK && err != Z_STREAM_END) {
				fprintf(stderr,
					"inflate error: %d (%m)\n", err);
				return -1;
			}
			rest -= length;
			stream.next_out = payload;
			while (length > 0) {
				written = write(fd, stream.next_out, length);
				if (written < 0) {
					fprintf(stderr, "write error: %m\n");
					return -1;
				}
				length -= written;
			}
		}
		if (fd > 0 && close(fd) < 0) {
			fprintf(stderr, "failed to close \"%s/%s%s\": %m\n",
				root, dir, name);
			return -1;
		}
		name += strlen(name) + 1;
		index++;
		size++;
		mode++;
	}

	err = inflateEnd(&stream);

	if (err != Z_OK) {
		fprintf(stderr, "inflateEnd error: %d\n", err);
		return -1;
	}	    

	run_script(rpm, root, RPMTAG_POSTIN);

	return 0;
}

int
razor_rpm_close(struct razor_rpm *rpm)
{
	int err;

	free(rpm->dirs);
	err = munmap(rpm->map, rpm->size);
	free(rpm);

	return err;
}

int
razor_importer_add_rpm(struct razor_importer *importer, struct razor_rpm *rpm)
{
	razor_importer_begin_package(importer,
				     rpm->pool + ntohl(rpm->name->offset),
				     rpm->pool + ntohl(rpm->version->offset));

	import_properties(importer, &rpm->requires,
			  rpm->pool, RAZOR_PROPERTY_REQUIRES);
	import_properties(importer, &rpm->provides,
			  rpm->pool, RAZOR_PROPERTY_PROVIDES);
	import_properties(importer, &rpm->conflicts,
			  rpm->pool, RAZOR_PROPERTY_CONFLICTS);
	import_properties(importer, &rpm->obsoletes,
			  rpm->pool, RAZOR_PROPERTY_OBSOLETES);
	import_files(importer, rpm);

	razor_importer_finish_package(importer);

	return 0;
}
