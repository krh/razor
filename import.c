#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <expat.h>
#include <zlib.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmdb.h>
#include "sha1.h"
#include "razor.h"

static void
parse_package(struct razor_importer *importer, const char **atts, void *data)
{
	const char *name = NULL, *version = NULL;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = atts[i + 1];
		else if (strcmp(atts[i], "version") == 0)
			version = atts[i + 1];
	}

	if (name == NULL || version == NULL) {
		fprintf(stderr, "invalid package tag, "
			"missing name or version attributes\n");
		return;
	}

	razor_importer_begin_package(importer, name, version);
}

enum {
	RZR_REQUIRES, RZR_PROVIDES
};

static void
parse_property(struct razor_importer *importer, const char **atts, void *data)
{
	const char *name = NULL, *version = NULL;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = atts[i + 1];
		if (strcmp(atts[i], "version") == 0)
			version = atts[i + 1];
	}
	
	if (name == NULL) {
		fprintf(stderr, "invalid tag, missing name attribute\n");
		return;
	}

	switch ((int) data) {
	case RZR_REQUIRES:
		razor_importer_add_property(importer, name, version,
					    RAZOR_PROPERTY_REQUIRES);
		break;
	case RZR_PROVIDES:
		razor_importer_add_property(importer, name, version,
					    RAZOR_PROPERTY_PROVIDES);
		break;
	}
}

static void
start_element(void *data, const char *name, const char **atts)
{
	struct razor_importer *importer = data;

	if (strcmp(name, "package") == 0)
		parse_package(importer, atts, NULL);
	else if (strcmp(name, "requires") == 0)
		parse_property(importer, atts, (void *) RZR_REQUIRES);
	else if (strcmp(name, "provides") == 0)
		parse_property(importer, atts, (void*) RZR_PROVIDES);
}

static void
end_element (void *data, const char *name)
{
	struct razor_importer *importer = data;

	if (strcmp(name, "package") == 0)
		razor_importer_finish_package(importer);
}

static int
import_rzr_file(struct razor_importer *importer, const char *filename)
{
	SHA_CTX sha1;
	XML_Parser parser;
	int fd;
	void *p;
	struct stat stat;
	unsigned char hash[20];

	fd = open(filename, O_RDONLY);
	if (fstat(fd, &stat) < 0)
		return -1;
	p = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		return -1;

	parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, importer);
	XML_SetElementHandler(parser, start_element, end_element);
	if (XML_Parse(parser, p, stat.st_size, 1) == XML_STATUS_ERROR) {
		fprintf(stderr,
			"%s at line %ld, %s\n",
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

	munmap(p, stat.st_size);

	return 0;
}

struct razor_set *
razor_import_rzr_files(int count, const char *files[])
{
	struct razor_importer *importer;
	int i;

	importer = razor_importer_new();

	for (i = 0; i < count; i++) {
		if (import_rzr_file(importer, files[i]) < 0) {
			fprintf(stderr, "failed to import %s\n", files[i]);
			exit(-1);
		}
	}

	return razor_importer_finish(importer);
}

/* Import a yum filelist as a razor package set. */

enum {
	YUM_STATE_BEGIN,
	YUM_STATE_PACKAGE_NAME,
	YUM_STATE_CHECKSUM,
	YUM_STATE_REQUIRES,
	YUM_STATE_PROVIDES,
	YUM_STATE_OBSOLETES,
	YUM_STATE_CONFLICTS,
	YUM_STATE_FILE
};

struct yum_context {
	XML_Parser primary_parser;
	XML_Parser filelists_parser;
	XML_Parser current_parser;

	struct razor_importer *importer;
	struct import_property_context *current_property_context;
	char name[256], buffer[512], *p;
	char pkgid[128];
	int state;
};

static void
yum_primary_start_element(void *data, const char *name, const char **atts)
{
	struct yum_context *ctx = data;
	const char *n, *version, *release;
	char buffer[128];
	int i;

	if (strcmp(name, "name") == 0) {
		ctx->state = YUM_STATE_PACKAGE_NAME;
		ctx->p = ctx->name;
	} else if (strcmp(name, "version") == 0) {
		version = NULL;
		release = NULL;
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], "ver") == 0)
				version = atts[i + 1];
			else if (strcmp(atts[i], "rel") == 0)
				release = atts[i + 1];
		}
		if (version == NULL || release == NULL) {
			fprintf(stderr, "invalid version tag, "
				"missing version or  release attribute\n");
			return;
		}

		snprintf(buffer, sizeof buffer, "%s-%s", version, release);
		razor_importer_begin_package(ctx->importer, ctx->name, buffer);
	} else if (strcmp(name, "checksum") == 0) {
		ctx->p = ctx->pkgid;
		ctx->state = YUM_STATE_CHECKSUM;
	} else if (strcmp(name, "rpm:requires") == 0) {
		ctx->state = YUM_STATE_REQUIRES;
	} else if (strcmp(name, "rpm:provides") == 0) {
		ctx->state = YUM_STATE_PROVIDES;
	} else if (strcmp(name, "rpm:obsoletes") == 0) {
		ctx->state = YUM_STATE_OBSOLETES;
	} else if (strcmp(name, "rpm:conflicts") == 0) {
		ctx->state = YUM_STATE_CONFLICTS;
	} else if (strcmp(name, "rpm:entry") == 0 &&
		   ctx->state != YUM_STATE_BEGIN) {
		n = NULL;
		version = NULL;
		release = NULL;
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], "name") == 0)
				n = atts[i + 1];
			else if (strcmp(atts[i], "ver") == 0)
				version = atts[i + 1];
			else if (strcmp(atts[i], "rel") == 0)
				release = atts[i + 1];
		}

		if (n == NULL) {
			fprintf(stderr, "invalid rpm:entry, "
				"missing name or version attributes\n");
			return;
		}

		if (version && release)
			snprintf(buffer, sizeof buffer,
				 "%s-%s", version, release);
		else if (version)
			strcpy(buffer, version);
		else
			buffer[0] = '\0';
			
		switch (ctx->state) {
		case YUM_STATE_REQUIRES:
			razor_importer_add_property(ctx->importer, n, buffer,
						    RAZOR_PROPERTY_REQUIRES);
			break;
		case YUM_STATE_PROVIDES:
			razor_importer_add_property(ctx->importer, n, buffer,
						    RAZOR_PROPERTY_PROVIDES);
			break;
		case YUM_STATE_OBSOLETES:
			razor_importer_add_property(ctx->importer, n, buffer,
						    RAZOR_PROPERTY_OBSOLETES);
			break;
		case YUM_STATE_CONFLICTS:
			razor_importer_add_property(ctx->importer, n, buffer,
						    RAZOR_PROPERTY_CONFLICTS);
			break;
		}
	}
}

static void
yum_primary_end_element (void *data, const char *name)
{
	struct yum_context *ctx = data;

	switch (ctx->state) {
	case YUM_STATE_PACKAGE_NAME:
	case YUM_STATE_CHECKSUM:
	case YUM_STATE_FILE:
		ctx->state = YUM_STATE_BEGIN;
		break;
	}

	if (strcmp(name, "package") == 0) {
		XML_StopParser(ctx->current_parser, XML_TRUE);
		ctx->current_parser = ctx->filelists_parser;
	}
}

static void
yum_character_data (void *data, const XML_Char *s, int len)
{
	struct yum_context *ctx = data;

	switch (ctx->state) {
	case YUM_STATE_PACKAGE_NAME:
	case YUM_STATE_CHECKSUM:
	case YUM_STATE_FILE:
		memcpy(ctx->p, s, len);
		ctx->p += len;
		*ctx->p = '\0';
		break;
	}
}

static void
yum_filelists_start_element(void *data, const char *name, const char **atts)
{
	struct yum_context *ctx = data;
	const char *pkg, *pkgid;
	int i;

	if (strcmp(name, "package") == 0) {
		pkg = NULL;
		pkgid = NULL;
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], "name") == 0)
				pkg = atts[i + 1];
			else if (strcmp(atts[i], "pkgid") == 0)
				pkgid = atts[i + 1];
		}
		if (strcmp(pkgid, ctx->pkgid) != 0)
			fprintf(stderr, "primary.xml and filelists.xml "
				"mismatch for %s: %s vs %s",
				pkg, pkgid, ctx->pkgid);
	} else if (strcmp(name, "file") == 0) {
		ctx->state = YUM_STATE_FILE;
		ctx->p = ctx->buffer;
	}
}


static void
yum_filelists_end_element (void *data, const char *name)
{
	struct yum_context *ctx = data;

	ctx->state = YUM_STATE_BEGIN;
	if (strcmp(name, "package") == 0) {
		XML_StopParser(ctx->current_parser, XML_TRUE);
		ctx->current_parser = ctx->primary_parser;
		razor_importer_finish_package(ctx->importer);
	} else if (strcmp(name, "file") == 0)
		razor_importer_add_file(ctx->importer, ctx->buffer);

}

#define XML_BUFFER_SIZE 4096

struct razor_set *
razor_set_create_from_yum(void)
{
	struct yum_context ctx;
	void *buf;
	int len, ret;
	gzFile primary, filelists;
	XML_ParsingStatus status;

	ctx.importer = razor_importer_new();	
	ctx.state = YUM_STATE_BEGIN;

	ctx.primary_parser = XML_ParserCreate(NULL);
	XML_SetUserData(ctx.primary_parser, &ctx);
	XML_SetElementHandler(ctx.primary_parser,
			      yum_primary_start_element,
			      yum_primary_end_element);
	XML_SetCharacterDataHandler(ctx.primary_parser,
				    yum_character_data);

	ctx.filelists_parser = XML_ParserCreate(NULL);
	XML_SetUserData(ctx.filelists_parser, &ctx);
	XML_SetElementHandler(ctx.filelists_parser,
			      yum_filelists_start_element,
			      yum_filelists_end_element);
	XML_SetCharacterDataHandler(ctx.filelists_parser,
				    yum_character_data);

	primary = gzopen("primary.xml.gz", "rb");
	if (primary == NULL)
		return NULL;
	filelists = gzopen("filelists.xml.gz", "rb");
	if (filelists == NULL)
		return NULL;

	ctx.current_parser = ctx.primary_parser;

	do {
		XML_GetParsingStatus(ctx.current_parser, &status);
		switch (status.parsing) {
		case XML_SUSPENDED:
			ret = XML_ResumeParser(ctx.current_parser);
			break;
		case XML_PARSING:
		case XML_INITIALIZED:
			buf = XML_GetBuffer(ctx.current_parser,
					    XML_BUFFER_SIZE);
			if (ctx.current_parser == ctx.primary_parser)
				len = gzread(primary, buf, XML_BUFFER_SIZE);
			else
				len = gzread(filelists, buf, XML_BUFFER_SIZE);
			if (len < 0) {
				fprintf(stderr,
					"couldn't read input: %s\n",
					strerror(errno));
				return NULL;
			}

			XML_ParseBuffer(ctx.current_parser, len, len == 0);
			break;
		case XML_FINISHED:
			break;
		}
	} while (status.parsing != XML_FINISHED);


	XML_ParserFree(ctx.primary_parser);
	XML_ParserFree(ctx.filelists_parser);

	gzclose(primary);
	gzclose(filelists);

	return razor_importer_finish(ctx.importer);
}

union rpm_entry {
	void *p;
	char *string;
	char **list;
	unsigned int *flags;
};

struct razor_set *
razor_set_create_from_rpmdb(void)
{
	struct razor_importer *importer;
	rpmdbMatchIterator iter;
	Header h;
	int_32 type, count, i;
	union rpm_entry name, version, release;
	union rpm_entry property_names, property_versions, property_flags;
	union rpm_entry basenames, dirnames, dirindexes;
	char filename[PATH_MAX];
	rpmdb db;

	rpmReadConfigFiles(NULL, NULL);

	if (rpmdbOpen("", &db, O_RDONLY, 0644) != 0) {
		fprintf(stderr, "cannot open rpm database\n");
		exit(1);
	}

	importer = razor_importer_new();

	iter = rpmdbInitIterator(db, 0, NULL, 0);
	while (h = rpmdbNextIterator(iter), h != NULL) {
		headerGetEntry(h, RPMTAG_NAME, &type, &name.p, &count);
		headerGetEntry(h, RPMTAG_VERSION, &type, &version.p, &count);
		headerGetEntry(h, RPMTAG_RELEASE, &type, &release.p, &count);
		snprintf(filename, sizeof filename, "%s-%s",
			 version.string, release.string);
		razor_importer_begin_package(importer, name.string, filename);

		headerGetEntry(h, RPMTAG_REQUIRENAME, &type,
			       &property_names.p, &count);
		headerGetEntry(h, RPMTAG_REQUIREVERSION, &type,
			       &property_versions.p, &count);
		headerGetEntry(h, RPMTAG_REQUIREFLAGS, &type,
			       &property_flags.p, &count);
		for (i = 0; i < count; i++)
			razor_importer_add_property(importer,
						    property_names.list[i],
						    property_versions.list[i],
						    RAZOR_PROPERTY_REQUIRES);

		headerGetEntry(h, RPMTAG_PROVIDENAME, &type,
			       &property_names.p, &count);
		headerGetEntry(h, RPMTAG_PROVIDEVERSION, &type,
			       &property_versions.p, &count);
		headerGetEntry(h, RPMTAG_PROVIDEFLAGS, &type,
			       &property_flags.p, &count);
		for (i = 0; i < count; i++)
			razor_importer_add_property(importer,
						    property_names.list[i],
						    property_versions.list[i],
						    RAZOR_PROPERTY_PROVIDES);

		headerGetEntry(h, RPMTAG_OBSOLETENAME, &type,
			       &property_names.p, &count);
		headerGetEntry(h, RPMTAG_OBSOLETEVERSION, &type,
			       &property_versions.p, &count);
		headerGetEntry(h, RPMTAG_OBSOLETEFLAGS, &type,
			       &property_flags.p, &count);
		for (i = 0; i < count; i++)
			razor_importer_add_property(importer,
						    property_names.list[i],
						    property_versions.list[i],
						    RAZOR_PROPERTY_OBSOLETES);

		headerGetEntry(h, RPMTAG_CONFLICTNAME, &type,
			       &property_names.p, &count);
		headerGetEntry(h, RPMTAG_CONFLICTVERSION, &type,
			       &property_versions.p, &count);
		headerGetEntry(h, RPMTAG_CONFLICTFLAGS, &type,
			       &property_flags.p, &count);
		for (i = 0; i < count; i++)
			razor_importer_add_property(importer,
						    property_names.list[i],
						    property_versions.list[i],
						    RAZOR_PROPERTY_CONFLICTS);

		headerGetEntry(h, RPMTAG_BASENAMES, &type,
			       &basenames.p, &count);
		headerGetEntry(h, RPMTAG_DIRNAMES, &type,
			       &dirnames.p, &count);
		headerGetEntry(h, RPMTAG_DIRINDEXES, &type,
			       &dirindexes.p, &count);
		for (i = 0; i < count; i++) {
			snprintf(filename, sizeof filename, "%s%s",
				 dirnames.list[dirindexes.flags[i]],
				 basenames.list[i]);
			razor_importer_add_file(importer, filename);
		}

		razor_importer_finish_package(importer);
	}

	rpmdbClose(db);

	return razor_importer_finish(importer);
}
