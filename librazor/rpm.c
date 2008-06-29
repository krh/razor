/*
 * Copyright (C) 2008  Kristian Høgsberg <krh@redhat.com>
 * Copyright (C) 2008  Red Hat, Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <assert.h>

#include "razor.h"
#include "razor-internal.h"

#define	RPM_LEAD_SIZE 96

enum {
    PIPE	=  1,	/*!< pipe/fifo */
    CDEV	=  2,	/*!< character device */
    XDIR	=  4,	/*!< directory */
    BDEV	=  6,	/*!< block device */
    REG		=  8,	/*!< regular file */
    LINK	= 10,	/*!< hard link */
    SOCK	= 12	/*!< socket */
};

enum {
    RPMSENSE_LESS		= 1 << 1,
    RPMSENSE_GREATER		= 1 << 2,
    RPMSENSE_EQUAL		= 1 << 3,
    RPMSENSE_PREREQ		= 1 << 6,
    RPMSENSE_SCRIPT_PRE		= 1 << 9,
    RPMSENSE_SCRIPT_POST	= 1 << 10,
    RPMSENSE_SCRIPT_PREUN	= 1 << 11,
    RPMSENSE_SCRIPT_POSTUN	= 1 << 12,
};

enum {
    RPMTAG_NAME  		= 1000,	/* s */
    RPMTAG_VERSION		= 1001,	/* s */
    RPMTAG_RELEASE		= 1002,	/* s */
    RPMTAG_EPOCH   		= 1003,	/* i */
    RPMTAG_SUMMARY		= 1004,	/* s{} */
    RPMTAG_DESCRIPTION		= 1005,	/* s{} */
    RPMTAG_BUILDTIME		= 1006,	/* i */
    RPMTAG_BUILDHOST		= 1007,	/* s */
    RPMTAG_INSTALLTIME		= 1008,	/* i */
    RPMTAG_SIZE			= 1009,	/* i */
    RPMTAG_DISTRIBUTION		= 1010,	/* s */
    RPMTAG_VENDOR		= 1011,	/* s */
    RPMTAG_GIF			= 1012,	/* x */
    RPMTAG_XPM			= 1013,	/* x */
    RPMTAG_LICENSE		= 1014,	/* s */
    RPMTAG_PACKAGER		= 1015,	/* s */
    RPMTAG_GROUP		= 1016,	/* s{} */
    RPMTAG_CHANGELOG		= 1017, /*!< s[] internal */
    RPMTAG_SOURCE		= 1018,	/* s[] */
    RPMTAG_PATCH		= 1019,	/* s[] */
    RPMTAG_URL			= 1020,	/* s */
    RPMTAG_OS			= 1021,	/* s legacy used int */
    RPMTAG_ARCH			= 1022,	/* s legacy used int */
    RPMTAG_PREIN		= 1023,	/* s */
    RPMTAG_POSTIN		= 1024,	/* s */
    RPMTAG_PREUN		= 1025,	/* s */
    RPMTAG_POSTUN		= 1026,	/* s */
    RPMTAG_OLDFILENAMES		= 1027, /* s[] obsolete */
    RPMTAG_FILESIZES		= 1028,	/* i */
    RPMTAG_FILESTATES		= 1029, /* c */
    RPMTAG_FILEMODES		= 1030,	/* h */
    RPMTAG_FILEUIDS		= 1031, /*!< internal */
    RPMTAG_FILEGIDS		= 1032, /*!< internal */
    RPMTAG_FILERDEVS		= 1033,	/* h */
    RPMTAG_FILEMTIMES		= 1034, /* i */
    RPMTAG_FILEMD5S		= 1035,	/* s[] */
    RPMTAG_FILELINKTOS		= 1036,	/* s[] */
    RPMTAG_FILEFLAGS		= 1037,	/* i */
    RPMTAG_ROOT			= 1038, /*!< internal - obsolete */
    RPMTAG_FILEUSERNAME		= 1039,	/* s[] */
    RPMTAG_FILEGROUPNAME	= 1040,	/* s[] */
    RPMTAG_EXCLUDE		= 1041, /*!< internal - obsolete */
    RPMTAG_EXCLUSIVE		= 1042, /*!< internal - obsolete */
    RPMTAG_ICON			= 1043,
    RPMTAG_SOURCERPM		= 1044,	/* s */
    RPMTAG_FILEVERIFYFLAGS	= 1045,	/* i */
    RPMTAG_ARCHIVESIZE		= 1046,	/* i */
    RPMTAG_PROVIDENAME		= 1047,	/* s[] */
    RPMTAG_REQUIREFLAGS		= 1048,	/* i */
    RPMTAG_REQUIRENAME		= 1049,	/* s[] */
    RPMTAG_REQUIREVERSION	= 1050,	/* s[] */
    RPMTAG_NOSOURCE		= 1051, /*!< internal */
    RPMTAG_NOPATCH		= 1052, /*!< internal */
    RPMTAG_CONFLICTFLAGS	= 1053, /* i */
    RPMTAG_CONFLICTNAME		= 1054,	/* s[] */
    RPMTAG_CONFLICTVERSION	= 1055,	/* s[] */
    RPMTAG_DEFAULTPREFIX	= 1056, /*!< internal - deprecated */
    RPMTAG_BUILDROOT		= 1057, /*!< internal */
    RPMTAG_INSTALLPREFIX	= 1058, /*!< internal - deprecated */
    RPMTAG_EXCLUDEARCH		= 1059,
    RPMTAG_EXCLUDEOS		= 1060,
    RPMTAG_EXCLUSIVEARCH	= 1061,
    RPMTAG_EXCLUSIVEOS		= 1062,
    RPMTAG_AUTOREQPROV		= 1063, /*!< internal */
    RPMTAG_RPMVERSION		= 1064,	/* s */
    RPMTAG_TRIGGERSCRIPTS	= 1065,	/* s[] */
    RPMTAG_TRIGGERNAME		= 1066,	/* s[] */
    RPMTAG_TRIGGERVERSION	= 1067,	/* s[] */
    RPMTAG_TRIGGERFLAGS		= 1068,	/* i */
    RPMTAG_TRIGGERINDEX		= 1069,	/* i */
    RPMTAG_VERIFYSCRIPT		= 1079,	/* s */
    RPMTAG_CHANGELOGTIME	= 1080,	/* i */
    RPMTAG_CHANGELOGNAME	= 1081,	/* s[] */
    RPMTAG_CHANGELOGTEXT	= 1082,	/* s[] */
    RPMTAG_BROKENMD5		= 1083, /*!< internal - obsolete */
    RPMTAG_PREREQ		= 1084, /*!< internal */
    RPMTAG_PREINPROG		= 1085,	/* s */
    RPMTAG_POSTINPROG		= 1086,	/* s */
    RPMTAG_PREUNPROG		= 1087,	/* s */
    RPMTAG_POSTUNPROG		= 1088,	/* s */
    RPMTAG_BUILDARCHS		= 1089,
    RPMTAG_OBSOLETENAME		= 1090,	/* s[] */
    RPMTAG_VERIFYSCRIPTPROG	= 1091,	/* s */
    RPMTAG_TRIGGERSCRIPTPROG	= 1092,	/* s */
    RPMTAG_DOCDIR		= 1093, /*!< internal */
    RPMTAG_COOKIE		= 1094,	/* s */
    RPMTAG_FILEDEVICES		= 1095,	/* i */
    RPMTAG_FILEINODES		= 1096,	/* i */
    RPMTAG_FILELANGS		= 1097,	/* s[] */
    RPMTAG_PREFIXES		= 1098,	/* s[] */
    RPMTAG_INSTPREFIXES		= 1099,	/* s[] */
    RPMTAG_TRIGGERIN		= 1100, /*!< internal */
    RPMTAG_TRIGGERUN		= 1101, /*!< internal */
    RPMTAG_TRIGGERPOSTUN	= 1102, /*!< internal */
    RPMTAG_AUTOREQ		= 1103, /*!< internal */
    RPMTAG_AUTOPROV		= 1104, /*!< internal */
    RPMTAG_CAPABILITY		= 1105, /*!< internal - obsolete */
    RPMTAG_SOURCEPACKAGE	= 1106, /*!< i src.rpm header marker */
    RPMTAG_OLDORIGFILENAMES	= 1107, /*!< internal - obsolete */
    RPMTAG_BUILDPREREQ		= 1108, /*!< internal */
    RPMTAG_BUILDREQUIRES	= 1109, /*!< internal */
    RPMTAG_BUILDCONFLICTS	= 1110, /*!< internal */
    RPMTAG_BUILDMACROS		= 1111, /*!< internal - unused */
    RPMTAG_PROVIDEFLAGS		= 1112,	/* i */
    RPMTAG_PROVIDEVERSION	= 1113,	/* s[] */
    RPMTAG_OBSOLETEFLAGS	= 1114,	/* i */
    RPMTAG_OBSOLETEVERSION	= 1115,	/* s[] */
    RPMTAG_DIRINDEXES		= 1116,	/* i */
    RPMTAG_BASENAMES		= 1117,	/* s[] */
    RPMTAG_DIRNAMES		= 1118,	/* s[] */
    RPMTAG_ORIGDIRINDEXES	= 1119, /*!< internal */
    RPMTAG_ORIGBASENAMES	= 1120, /*!< internal */
    RPMTAG_ORIGDIRNAMES		= 1121, /*!< internal */
    RPMTAG_OPTFLAGS		= 1122,	/* s */
    RPMTAG_DISTURL		= 1123,	/* s */
    RPMTAG_PAYLOADFORMAT	= 1124,	/* s */
    RPMTAG_PAYLOADCOMPRESSOR	= 1125,	/* s */
    RPMTAG_PAYLOADFLAGS		= 1126,	/* s */
    RPMTAG_INSTALLCOLOR		= 1127, /*!< i transaction color when installed */
    RPMTAG_INSTALLTID		= 1128,	/* i */
    RPMTAG_REMOVETID		= 1129,	/* i */
    RPMTAG_SHA1RHN		= 1130, /*!< internal - obsolete */
    RPMTAG_RHNPLATFORM		= 1131,	/* s */
    RPMTAG_PLATFORM		= 1132,	/* s */
    RPMTAG_PATCHESNAME		= 1133, /*!< placeholder (SuSE) */
    RPMTAG_PATCHESFLAGS		= 1134, /*!< placeholder (SuSE) */
    RPMTAG_PATCHESVERSION	= 1135, /*!< placeholder (SuSE) */
    RPMTAG_CACHECTIME		= 1136,	/* i */
    RPMTAG_CACHEPKGPATH		= 1137,	/* s */
    RPMTAG_CACHEPKGSIZE		= 1138,	/* i */
    RPMTAG_CACHEPKGMTIME	= 1139,	/* i */
    RPMTAG_FILECOLORS		= 1140,	/* i */
    RPMTAG_FILECLASS		= 1141,	/* i */
    RPMTAG_CLASSDICT		= 1142,	/* s[] */
    RPMTAG_FILEDEPENDSX		= 1143,	/* i */
    RPMTAG_FILEDEPENDSN		= 1144,	/* i */
    RPMTAG_DEPENDSDICT		= 1145,	/* i */
    RPMTAG_SOURCEPKGID		= 1146,	/* x */
    RPMTAG_FILECONTEXTS		= 1147,	/* s[] */
    RPMTAG_FSCONTEXTS		= 1148,	/*!< s[] extension */
    RPMTAG_RECONTEXTS		= 1149,	/*!< s[] extension */
    RPMTAG_POLICIES		= 1150,	/*!< s[] selinux *.te policy file. */
    RPMTAG_PRETRANS		= 1151,	/* s */
    RPMTAG_POSTTRANS		= 1152,	/* s */
    RPMTAG_PRETRANSPROG		= 1153,	/* s */
    RPMTAG_POSTTRANSPROG	= 1154,	/* s */
    RPMTAG_DISTTAG		= 1155,	/* s */
    RPMTAG_SUGGESTSNAME		= 1156,	/* s[] extension placeholder */
    RPMTAG_SUGGESTSVERSION	= 1157,	/* s[] extension placeholder */
    RPMTAG_SUGGESTSFLAGS	= 1158,	/* i   extension placeholder */
    RPMTAG_ENHANCESNAME		= 1159,	/* s[] extension placeholder */
    RPMTAG_ENHANCESVERSION	= 1160,	/* s[] extension placeholder */
    RPMTAG_ENHANCESFLAGS	= 1161,	/* i   extension placeholder */
    RPMTAG_PRIORITY		= 1162, /* i   extension placeholder */
    RPMTAG_CVSID		= 1163, /* s */
    RPMTAG_TRIGGERPREIN		= 1171, /*!< internal */
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

static uint32_t
rpm_to_razor_flags(uint32_t flags)
{
	uint32_t razor_flags;

	razor_flags = 0;
	if (flags & RPMSENSE_LESS)
		razor_flags |= RAZOR_PROPERTY_LESS;
	if (flags & RPMSENSE_EQUAL)
		razor_flags |= RAZOR_PROPERTY_EQUAL;
	if (flags & RPMSENSE_GREATER)
		razor_flags |= RAZOR_PROPERTY_GREATER;

	if (flags & RPMSENSE_SCRIPT_PRE)
		razor_flags |= RAZOR_PROPERTY_PRE;
	if (flags & RPMSENSE_SCRIPT_POST)
		razor_flags |= RAZOR_PROPERTY_POST;
	if (flags & RPMSENSE_SCRIPT_PREUN)
		razor_flags |= RAZOR_PROPERTY_PREUN;
	if (flags & RPMSENSE_SCRIPT_POSTUN)
		razor_flags |= RAZOR_PROPERTY_POSTUN;
	
	return razor_flags;
}

static void
import_properties(struct razor_importer *importer, uint32_t type,
		  struct razor_rpm *rpm,
		  int name_tag, int version_tag, int flags_tag)
{
	const char *name, *version;
	const uint32_t *flags;
	uint32_t f;
	unsigned int i, count;

	name = razor_rpm_get_indirect(rpm, name_tag, &count);
	if (name == NULL)
		return;

	flags = razor_rpm_get_indirect(rpm, flags_tag, &count);

	version = razor_rpm_get_indirect(rpm, version_tag, &count);
	for (i = 0; i < count; i++) {
		f = rpm_to_razor_flags(ntohl(flags[i]));
		razor_importer_add_property(importer, name, f | type, version);
		name += strlen(name) + 1;
		version += strlen(version) + 1;
	}
}

static void
import_files(struct razor_importer *importer, struct razor_rpm *rpm)
{
	const char *name;
	const uint32_t *index;
	unsigned int i, count;
	char buffer[256];

	if (rpm->dirs == NULL)
		return;

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

RAZOR_EXPORT struct razor_rpm *
razor_rpm_open(const char *filename)
{
	struct razor_rpm *rpm;
	struct rpm_header_index *base, *index;
	struct stat buf;
	unsigned int count, i, nindex, hsize;
	const char *name;
	int fd;

	assert (filename != NULL);

	rpm = malloc(sizeof *rpm);
	if (rpm == NULL)
		return NULL;
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
	if (name) {
		rpm->dirs = calloc(count, sizeof *rpm->dirs);
		for (i = 0; i < count; i++) {
			rpm->dirs[i] = name;
			name += strlen(name) + 1;
		}
	} else {
		name = razor_rpm_get_indirect(rpm, RPMTAG_OLDFILENAMES,
					      &count);
		if (name) {
			fprintf(stderr, "old filenames not supported\n");
			return NULL;
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

	if (installer->rest > sizeof installer->buffer)
		length = sizeof installer->buffer;
	else
		length = installer->rest;

	installer->stream.next_out = installer->buffer;
	installer->stream.avail_out = length;
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
installer_align(struct installer *installer, size_t size)
{
	unsigned char buffer[4];
	int err;

	installer->stream.next_out = buffer;
	installer->stream.avail_out =
		(size - installer->stream.total_out) & (size - 1);

	if (installer->stream.avail_out == 0)
		return 0;

	err = inflate(&installer->stream, Z_SYNC_FLUSH);
	if (err != Z_OK && err != Z_STREAM_END) {
		fprintf(stderr, "inflate error: %d (%m)\n", err);
		return -1;
	}

	return 0;
}

static int
create_path(struct installer *installer, const char *path, unsigned int mode)
{
	char buffer[PATH_MAX];
	struct stat buf;
	int fd, ret;

	if (razor_create_dir(installer->root, path) < 0)
		return -1;

	snprintf(buffer, sizeof buffer, "%s%s", installer->root, path);

	switch (mode >> 12) {
	case REG:
		/* FIXME: handle the case where a file is already there. */
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
		ret = mkdir(buffer, mode & 0x1ff);
		if (ret == 0 || errno != EEXIST)
			return ret;
		if (stat(buffer, &buf) || !S_ISDIR(buf.st_mode)) {
			/* FIXME: also check that mode match. */
			fprintf(stderr,
				"%s exists but is not a directory\n", buffer);
			return -1;
		}
		return 0;
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
		return 0;
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
			exit(-1);
		}
		if (close(fd[0]) < 0 || close(fd[1]) < 0) {
			fprintf(stderr, "failed to close pipe, %m\n");
			exit(-1);
		}
		if (chroot(installer->root) < 0) {
			fprintf(stderr, "failed to chroot to %s, %m\n",
				installer->root);
			exit(-1);
		}
		printf("executing program %s in chroot %s\n",
		       program, installer->root);
		if (execl(program, program, NULL)) {
			fprintf(stderr, "failed to exec %s, %m\n", program);
			exit(-1);
		}
	} else {
		if (script && razor_write(fd[1], script, strlen(script)) < 0) {
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
		if (status)
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

static unsigned long
fixed_hex_to_ulong(const char *hex, int length)
{
	long l;
	int i;

	for (i = 0, l = 0; i < length; i++) {
		if (hex[i] < 'a')
			l = l * 16 + hex[i] - '0';
		else
			l = l * 16 + hex[i] - 'a' + 10;
	}

	return l;
}

RAZOR_EXPORT int
razor_rpm_install(struct razor_rpm *rpm, const char *root)
{
	struct installer installer;
	struct cpio_file_header *header;
	struct stat buf;
	unsigned int mode;
	char *path;
	size_t filesize;

	assert (rpm != NULL);
	assert (root != NULL);

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

	while (installer.stream.avail_in > 0) {
		installer.rest = sizeof *header;
		if (installer_inflate(&installer))
			return -1;

		header = (struct cpio_file_header *) installer.buffer;
		mode = fixed_hex_to_ulong(header->mode, sizeof header->mode);
		filesize = fixed_hex_to_ulong(header->filesize,
					      sizeof header->filesize);

		installer.rest = fixed_hex_to_ulong(header->namesize,
						    sizeof header->namesize);

		if (installer_inflate(&installer) ||
		    installer_align(&installer, 4))
			return -1;

		path = (char *) installer.buffer;
		/* This convention is so lame... */
		if (strcmp(path, "TRAILER!!!") == 0)
			break;

		installer.rest = filesize;
		if (create_path(&installer, path + 1, mode) < 0)
			return -1;
		if (installer_align(&installer, 4))
			return -1;
	}

	if (installer_finish(&installer))
		return -1;

	run_script(&installer, RPMTAG_POSTINPROG, RPMTAG_POSTIN);

	return 0;
}

RAZOR_EXPORT int
razor_rpm_close(struct razor_rpm *rpm)
{
	int err;

	assert (rpm != NULL);

	free(rpm->dirs);
	err = munmap(rpm->map, rpm->size);
	free(rpm);

	return err;
}

RAZOR_EXPORT int
razor_importer_add_rpm(struct razor_importer *importer, struct razor_rpm *rpm)
{
	const char *name, *version, *release, *arch;
	const char *summary, *description, *url, *license;
	const uint32_t *epoch;
	char evr[128], buf[16];

	assert (importer != NULL);
	assert (rpm != NULL);

	name = razor_rpm_get_indirect(rpm, RPMTAG_NAME, NULL);
	epoch = razor_rpm_get_indirect(rpm, RPMTAG_EPOCH, NULL);
	version = razor_rpm_get_indirect(rpm, RPMTAG_VERSION, NULL);
	release = razor_rpm_get_indirect(rpm, RPMTAG_RELEASE, NULL);
	arch = razor_rpm_get_indirect(rpm, RPMTAG_ARCH, NULL);

	summary = razor_rpm_get_indirect(rpm, RPMTAG_SUMMARY, NULL);
	description = razor_rpm_get_indirect(rpm, RPMTAG_DESCRIPTION, NULL);
	url = razor_rpm_get_indirect(rpm, RPMTAG_URL, NULL);
	license = razor_rpm_get_indirect(rpm, RPMTAG_LICENSE, NULL);

	if (epoch) {
		snprintf(buf, sizeof buf, "%u", ntohl(*epoch));
		razor_build_evr(evr, sizeof evr, buf, version, release);
	} else {
		razor_build_evr(evr, sizeof evr, NULL, version, release);
	}
	razor_importer_begin_package(importer, name, evr, arch);

	razor_importer_add_details(importer, summary, description, url,
				   license);

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
