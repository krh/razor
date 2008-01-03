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
#include "razor-internal.h"

#define	RPM_LEAD_SIZE 96

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

struct razor_rpm {
	struct rpm_header *signature;
	struct rpm_header *header;
	const char **dirs;
	const char *pool;
	void *map;
	size_t size;
	void *payload;
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

static const void *
razor_rpm_get_indirect(struct razor_rpm *rpm,
		       unsigned int tag, unsigned int *count)
{
	struct rpm_header_index *index;

	index = razor_rpm_get_header(rpm, tag);
	if (index != NULL) {
		if (count)
			*count = ntohl(index->count);

		return rpm->pool + ntohl(index->offset);
	}

	return NULL;
}

static void
import_properties(struct razor_importer *importer, unsigned long type,
		  struct razor_rpm *rpm,
		  int name_tag, int version_tag, int flags_tag)
{
	const char *name, *version;
	unsigned int i, count;

	name = razor_rpm_get_indirect(rpm, name_tag, &count);
	if (name == NULL)
		return;

	/* FIXME: Concat version and release. */
	version = razor_rpm_get_indirect(rpm, version_tag, &count);
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
	const unsigned long *index;
	unsigned int i, count;
	char buffer[256];

	/* assert: count is the same for all arrays */

	index = razor_rpm_get_indirect(rpm, RPMTAG_DIRINDEXES, &count);
	name = razor_rpm_get_indirect(rpm, RPMTAG_BASENAMES, &count);
	for (i = 0; i < count; i++) {
		snprintf(buffer, sizeof buffer,
			 "%s%s", rpm->dirs[ntohl(*index)], name);
		razor_importer_add_file(importer, buffer);
		name += strlen(name) + 1;
		index++;
	}
}

struct razor_rpm *
razor_rpm_open(const char *filename)
{
	struct razor_rpm *rpm;
	struct rpm_header_index *base, *index;
	struct stat buf;
	unsigned int count, i, nindex, hsize;
	const char *name;
	int fd;

	rpm = malloc(sizeof *rpm);
	memset(rpm, 0, sizeof *rpm);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "couldn't open %s\n", filename);
		return NULL;
	}

	if (fstat(fd, &buf) < 0) {
		fprintf(stderr, "failed to stat %s (%m)\n", filename);
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

	/* Look up dir names now so we can index them directly. */
	name = razor_rpm_get_indirect(rpm, RPMTAG_DIRNAMES, &count);
	if (name == NULL) {
		fprintf(stderr, "old filename style not handled\n");
		return NULL;
	}

	rpm->dirs = calloc(count, sizeof *rpm->dirs);
	for (i = 0; i < count; i++) {
		rpm->dirs[i] = name;
		name += strlen(name) + 1;
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

struct installer {
	const char *root;
	struct razor_rpm *rpm;
	z_stream stream;
	unsigned char buffer[32768];
	size_t rest, length;
};

static int
installer_inflate(struct installer *installer)
{
	size_t length;
	int err;

	if (ALIGN(installer->rest, 4) > sizeof installer->buffer)
		length = sizeof installer->buffer;
	else
		length = installer->rest;

	installer->stream.next_out = installer->buffer;
	installer->stream.avail_out = ALIGN(length, 4);
	err = inflate(&installer->stream, Z_SYNC_FLUSH);
	if (err != Z_OK && err != Z_STREAM_END) {
		fprintf(stderr, "inflate error: %d (%m)\n", err);
		return -1;
	}

	installer->rest -= length;
	installer->length = length;

	return 0;
}

static int
create_path(struct installer *installer,
	    const char *path, const char *name, unsigned int mode)
{
	char buffer[PATH_MAX];
	int fd;

	if (razor_create_dir(installer->root, path) < 0)
		return -1;

	snprintf(buffer, sizeof buffer, "%s%s/%s",
		 installer->root, path, name);

	switch (mode >> 12) {
	case REG:
		fd = open(buffer, O_WRONLY | O_CREAT | O_TRUNC, mode & 0x1ff);
		if (fd < 0){
			fprintf(stderr, "failed to create file %s\n", buffer);
			return -1;
		}
		while (installer->rest > 0) {
			if (installer_inflate(installer)) {
				fprintf(stderr, "failed to inflate\n");
				return -1;
			}
			if (razor_write(fd, installer->buffer,
					installer->length)) {
				fprintf(stderr, "failed to write payload\n");
				return -1;
			}
		}
		if (close(fd) < 0) {
			fprintf(stderr, "failed to close %s: %m\n", buffer);
			return -1;
		}
		return 0;
	case XDIR:
		return mkdir(buffer, mode & 0x1ff);
	case PIPE:
	case CDEV:
	case BDEV:
	case SOCK:
		printf("%s: unhandled file type %d\n", buffer, mode >> 12);
		return 0;
	case LINK:
		if (installer_inflate(installer)) {
			fprintf(stderr, "failed to inflate\n");
			return -1;
		}
		if (installer->length >= sizeof installer->buffer) {
			fprintf(stderr, "link name too long\n");
			return -1;
		}
		installer->buffer[installer->length] = '\0';
		if (symlink((const char *) installer->buffer, buffer)) {
			fprintf(stderr, "failed to create symlink, %m\n");
			return -1;
		}
		return 0;
	default:
		printf("%s: unknown file type %d\n", buffer, mode >> 12);
		return 0;
	}
}

static int
run_script(struct installer *installer,
	   unsigned int program_tag, unsigned int script_tag)
{
	int pid, status, fd[2];
	const char *script = NULL, *program = NULL;

	program = razor_rpm_get_indirect(installer->rpm, program_tag, NULL);
	script = razor_rpm_get_indirect(installer->rpm, script_tag, NULL);
	if (program == NULL && script == NULL) {
		printf("no script or program for tags %d and %d\n",
		       program_tag, script_tag);
		return -1;
	} else if (program == NULL) {
		program = "/bin/sh";
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
			return -1;
		}
		if (chroot(installer->root) < 0) {
			fprintf(stderr, "failed to chroot to %s, %m\n",
				installer->root);
			return -1;
		}
		printf("executing program %s in chroot %s\n",
		       program, installer->root);
		if (execl(program, program, NULL)) {
			fprintf(stderr, "failed to exec %s, %m\n", program);
			exit(-1);
		}
	} else {
		if (script && write(fd[1], script, strlen(script)) < 0) {
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

static int
installer_init(struct installer *installer)
{
	unsigned char *gz_header;
	int method, flags, err;

	gz_header = installer->rpm->payload;
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

	installer->stream.zalloc = NULL;
	installer->stream.zfree = NULL;
	installer->stream.opaque = NULL;

	installer->stream.next_in  = gz_header + 10;
	installer->stream.avail_in =
		(installer->rpm->map + installer->rpm->size) -
		(void *) installer->stream.next_in;
	installer->stream.next_out = NULL;
	installer->stream.avail_out = 0;

	err = inflateInit2(&installer->stream, -MAX_WBITS);
	if (err != Z_OK) {
		fprintf(stderr, "inflateInit error: %d\n", err);
		return -1;
	}

	return 0;
}

static int
installer_finish(struct installer *installer)
{
	int err;

	err = inflateEnd(&installer->stream);

	if (err != Z_OK) {
		fprintf(stderr, "inflateEnd error: %d\n", err);
		return -1;
	}	    

	return 0;
}

int
razor_rpm_install(struct razor_rpm *rpm, const char *root)
{
	struct installer installer;
	unsigned int count, i, length;
	struct cpio_file_header *header;
	const unsigned long *size, *index, *flags;
	const unsigned short *mode;
	const char *name, *dir;
	struct stat buf;

	installer.rpm = rpm;
	installer.root = root;

	/* FIXME: Only do this before a transaction, not per rpm. */
	if (stat(root, &buf) < 0 || !S_ISDIR(buf.st_mode)) {
		fprintf(stderr,
			"root installation directory \"%s\" does not exist\n",
			root);
		return -1;
	}

	if (installer_init(&installer))
		return -1;

	run_script(&installer, RPMTAG_PREINPROG, RPMTAG_PREIN);

	name = razor_rpm_get_indirect(rpm, RPMTAG_BASENAMES, &count);
	size = razor_rpm_get_indirect(rpm, RPMTAG_FILESIZES, &count);
	index = razor_rpm_get_indirect(rpm, RPMTAG_DIRINDEXES, &count);
	mode = razor_rpm_get_indirect(rpm, RPMTAG_FILEMODES, &count);
	flags = razor_rpm_get_indirect(rpm, RPMTAG_FILEFLAGS, &count);

	for (i = 0; i < count; i++) {
		dir = rpm->dirs[ntohl(*index)];

		/* Skip past the cpio header block unless it's a ghost file,
		 * in which case doesn't appear in the cpio archive. */
		if (!(ntohl(*flags) & RPMFILE_GHOST)) {
			/* Plus two for the leading '.' and the terminating NUL. */
			length = sizeof *header + strlen(dir) + strlen(name) + 2;
			installer.rest = ALIGN(length, 4);
			if (installer_inflate(&installer))
				return -1;
		}

		installer.rest = ntohl(*size);
		if (create_path(&installer, dir, name, ntohs(*mode)) < 0)
			return -1;

		name += strlen(name) + 1;
		index++;
		size++;
		mode++;
		flags++;
	}

	if (installer_finish(&installer))
		return -1;

	run_script(&installer, RPMTAG_POSTINPROG, RPMTAG_POSTIN);

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
	const char *name, *version, *release;

	name = razor_rpm_get_indirect(rpm, RPMTAG_NAME, NULL);
	version = razor_rpm_get_indirect(rpm, RPMTAG_VERSION, NULL);
	release = razor_rpm_get_indirect(rpm, RPMTAG_RELEASE, NULL);

	/* FIXME: Concatenate version and release. */
	razor_importer_begin_package(importer, name, version);

	import_properties(importer, RAZOR_PROPERTY_REQUIRES, rpm,
			  RPMTAG_REQUIRENAME,
			  RPMTAG_REQUIREVERSION,
			  RPMTAG_REQUIREFLAGS);

	import_properties(importer, RAZOR_PROPERTY_PROVIDES, rpm,
			  RPMTAG_PROVIDENAME,
			  RPMTAG_PROVIDEVERSION,
			  RPMTAG_PROVIDEFLAGS);

	import_properties(importer, RAZOR_PROPERTY_OBSOLETES, rpm,
			  RPMTAG_OBSOLETENAME,
			  RPMTAG_OBSOLETEVERSION,
			  RPMTAG_OBSOLETEFLAGS);

	import_properties(importer, RAZOR_PROPERTY_CONFLICTS, rpm,
			  RPMTAG_CONFLICTNAME,
			  RPMTAG_CONFLICTVERSION,
			  RPMTAG_CONFLICTFLAGS);

	import_files(importer, rpm);

	razor_importer_finish_package(importer);

	return 0;
}
