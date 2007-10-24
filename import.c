#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <expat.h>
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
		razor_importer_add_requires(importer, name, version);
		break;
	case RZR_PROVIDES:
		razor_importer_add_provides(importer, name, version);
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
	YUM_STATE_REQUIRES,
	YUM_STATE_PROVIDES,
	YUM_STATE_FILE
};

struct yum_context {
	struct razor_importer *importer;
	struct import_property_context *current_property_context;
	char name[256], buffer[512], *p;
	int state;
};

static void
yum_start_element(void *data, const char *name, const char **atts)
{
	struct yum_context *ctx = data;
	const char *n, *version;
	int i;

	if (strcmp(name, "name") == 0) {
		ctx->state = YUM_STATE_PACKAGE_NAME;
		ctx->p = ctx->name;
	} else if (strcmp(name, "version") == 0) {
		version = NULL;
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], "ver") == 0)
				version = atts[i + 1];
		}
		razor_importer_begin_package(ctx->importer, ctx->name, version);
	} else if (strcmp(name, "rpm:requires") == 0) {
		ctx->state = YUM_STATE_REQUIRES;
	} else if (strcmp(name, "rpm:provides") == 0) {
		ctx->state = YUM_STATE_PROVIDES;
	} else if (strcmp(name, "rpm:entry") == 0 &&
		   ctx->state != YUM_STATE_BEGIN) {
		n = NULL;
		version = NULL;
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], "name") == 0)
				n = atts[i + 1];
			else if (strcmp(atts[i], "ver") == 0)
				version = atts[i + 1];
		}

		if (n == NULL) {
			fprintf(stderr, "invalid rpm:entry, "
				"missing name or version attributes\n");
			return;
		}

		switch (ctx->state) {
		case YUM_STATE_REQUIRES:
			razor_importer_add_requires(ctx->importer, n, version);
			break;
		case YUM_STATE_PROVIDES:
			razor_importer_add_provides(ctx->importer, n, version);
			break;
		}
	} else if (strcmp(name, "file") == 0) {
		ctx->state = YUM_STATE_FILE;
		ctx->p = ctx->buffer;
	}
}

static void
yum_end_element (void *data, const char *name)
{
	struct yum_context *ctx = data;

	ctx->state = YUM_STATE_BEGIN;
	if (strcmp(name, "package") == 0)
		razor_importer_finish_package(ctx->importer);
	else if (strcmp(name, "file") == 0)
		razor_importer_add_file(ctx->importer, ctx->buffer);
}

static void
yum_character_data (void *data, const XML_Char *s, int len)
{
	struct yum_context *ctx = data;

	switch (ctx->state) {
	case YUM_STATE_PACKAGE_NAME:
	case YUM_STATE_FILE:
		memcpy(ctx->p, s, len);
		ctx->p += len;
		*ctx->p = '\0';
		break;
	}
}

struct razor_set *
razor_set_create_from_yum_filelist(int fd)
{
	struct yum_context ctx;
	XML_Parser parser;
	char buf[4096];
	int len;

	ctx.importer = razor_importer_new();	

	parser = XML_ParserCreate(NULL);
	XML_SetUserData(parser, &ctx);
	XML_SetElementHandler(parser, yum_start_element, yum_end_element);
	XML_SetCharacterDataHandler(parser, yum_character_data);

	while (1) {
		len = read(fd, buf, sizeof buf);
		if (len < 0) {
			fprintf(stderr,
				"couldn't read input: %s\n", strerror(errno));
			return NULL;
		} else if (len == 0)
			break;

		if (XML_Parse(parser, buf, len, 0) == XML_STATUS_ERROR) {
			fprintf(stderr,
				"%s at line %ld\n",
				XML_ErrorString(XML_GetErrorCode(parser)),
				XML_GetCurrentLineNumber(parser));
			return NULL;
		}
	}

	XML_ParserFree(parser);

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
			razor_importer_add_requires(importer,
						    property_names.list[i],
						    property_versions.list[i]);

		headerGetEntry(h, RPMTAG_PROVIDENAME, &type,
			       &property_names.p, &count);
		headerGetEntry(h, RPMTAG_PROVIDEVERSION, &type,
			       &property_versions.p, &count);
		for (i = 0; i < count; i++)
			razor_importer_add_provides(importer,
						    property_names.list[i],
						    property_versions.list[i]);

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
