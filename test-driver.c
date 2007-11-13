#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <expat.h>

#include "razor.h"

#define XML_BUFFER_SIZE 4096

static void
parse_xml_file(const char *filename,
	       XML_StartElementHandler start,
	       XML_EndElementHandler end,
	       void *data)
{
	XML_Parser parser;
	char *buffer;
	int fd, len, err;

	parser = XML_ParserCreate(NULL);
	XML_SetElementHandler(parser, start, end);
	XML_SetUserData(parser, data);

	buffer = XML_GetBuffer(parser, XML_BUFFER_SIZE);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open: %m\n");
		exit(-1);
	}

	while (len = read(fd, buffer, XML_BUFFER_SIZE), len > 0) {
		err = XML_ParseBuffer(parser, len, len == 0);
		if (err == XML_STATUS_ERROR) {
			fprintf(stderr, "parse error at line %lu:\n%s\n",
				XML_GetCurrentLineNumber(parser),
				XML_ErrorString(XML_GetErrorCode(parser)));
			exit(-1);
		}
	}

	if (fd < 0) {
		fprintf(stderr, "read: %m\n");
		exit(-1);
	}

	close(fd);
}

struct test_set {
	char *name;
	struct razor_set *set;
	struct test_set *next;
};

struct test_context {
	struct razor_importer *importer;
	struct test_set *sets;
};

static void
get_atts(const char **atts, ...)
{
	va_list ap;
	const char *name, **ptr;
	int i;

	va_start(ap, atts);
	while (name = va_arg(ap, const char *), name != NULL) {
		ptr = va_arg(ap, const char **);
		for (i = 0; atts[i]; i += 2) {
			if (strcmp(atts[i], name) == 0)
				*ptr = atts[i + 1];
		}
	}
	va_end(ap);
}

static void
parse_property(struct test_context *ctx, const char **atts,
	       enum razor_property_type type)
{
	const char *name = NULL, *version = NULL;
	int i;

	for (i = 0; atts[i]; i += 2) {
		if (strcmp(atts[i], "name") == 0)
			name = atts[i + 1];
		else if (strcmp(atts[i], "eq") == 0)
			version = atts[i + 1];
	}

	if (name == NULL) {
		fprintf(stderr, "no name specified for property\n");
		exit(-1);
	}
	
	razor_importer_add_property(ctx->importer, name, version, type);
}

static void
start_test_sets_element(void *data, const char *element, const char **atts)
{
	struct test_context *ctx = data;
	struct test_set *set;
	const char *name, *version;

	if (strcmp(element, "set") == 0) {
		get_atts(atts, "name", &name, NULL);
		ctx->importer = razor_importer_new();	
		set = malloc(sizeof *set);
		set->name = strdup(name);
		set->next = ctx->sets;
		ctx->sets = set;
	} else if (strcmp(element, "package") == 0) {
		get_atts(atts, "name", &name, "version", &version, NULL);
		razor_importer_begin_package(ctx->importer, name, version);
	} else if (strcmp(element, "requires") == 0) {
		parse_property(ctx, atts, RAZOR_PROPERTY_REQUIRES);
	} else if (strcmp(element, "provides") == 0) {
		parse_property(ctx, atts, RAZOR_PROPERTY_PROVIDES);
	} else if (strcmp(element, "obsoletes") == 0) {
		parse_property(ctx, atts, RAZOR_PROPERTY_OBSOLETES);
	} else if (strcmp(element, "conflicts") == 0) {
		parse_property(ctx, atts, RAZOR_PROPERTY_CONFLICTS);
	} else if (strcmp(element, "file") == 0) {
		get_atts(atts, "name", &name, NULL);
		razor_importer_add_file(ctx->importer, name);		
	} else if (strcmp(element, "dir") == 0) {
		get_atts(atts, "name", &name, NULL);
		razor_importer_add_file(ctx->importer, name);		
	}
}

static void
end_test_sets_element (void *data, const char *name)
{
	struct test_context *ctx = data;

	if (strcmp(name, "set") == 0) {
		ctx->sets->set = razor_importer_finish(ctx->importer);
	} else if (strcmp(name, "package") == 0) {
		razor_importer_finish_package(ctx->importer);
	}
}

int main(int argc, char *argv[])
{
	struct test_context ctx;
	struct test_set *set;

	if (argc != 3) {
		fprintf(stderr, "usage: %s SETS-FILE TESTS-FILE\n", argv[0]);
		exit(-1);			
	}

	memset(&ctx, 0, sizeof ctx);
	parse_xml_file(argv[1],
		       start_test_sets_element,
		       end_test_sets_element,
		       &ctx);

	for (set = ctx.sets; set != NULL; set = set->next)
		printf("set %s\n", set->name);

	return 0;
}
