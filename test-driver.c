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
		fprintf(stderr, "failed to open %s: %m\n", filename);
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
	struct razor_package_iterator *package_iterator;
	struct razor_property_iterator *property_iterator;
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
		*ptr = NULL;
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

	get_atts(atts, "name", &name, "eq", &version, NULL);

	if (name == NULL) {
		fprintf(stderr, "no name specified for property\n");
		exit(-1);
	}
	
	razor_importer_add_property(ctx->importer, name, version, type);
}

static void
start_set_element(void *data, const char *element, const char **atts)
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
end_set_element (void *data, const char *name)
{
	struct test_context *ctx = data;

	if (strcmp(name, "set") == 0) {
		ctx->sets->set = razor_importer_finish(ctx->importer);
	} else if (strcmp(name, "package") == 0) {
		razor_importer_finish_package(ctx->importer);
	}
}

static struct razor_set *
lookup_set(struct test_context *ctx, const char *name)
{
	struct test_set *set;

	for (set = ctx->sets; set != NULL; set = set->next) {
		if (strcmp(set->name, name) == 0)
			return set->set;
	}

	return NULL;
}

static void
verify_begin(struct test_context *ctx, const char **atts)
{
	struct razor_set *set;
	const char *type, *name;

	get_atts(atts, "type", &type, "set", &name, NULL);
	set = lookup_set(ctx, name);
	if (set == NULL) {
		fprintf(stderr, "set %s not found\n", name);
		exit(-1);
	}

	if (strcmp(type, "packages") == 0) {
		ctx->package_iterator =
			razor_package_iterator_create(set);
	} else if (strcmp(type, "properties") == 0) {
		ctx->property_iterator =
			razor_property_iterator_create(set, NULL);
	} else {
		fprintf(stderr,
			"unknown compare type \"%s\"\n", type);
		exit(-1);
	}
}

static void
verify_end(struct test_context *ctx)
{
	struct razor_package *package;
	struct razor_property *property;
	const char *name, *version, *ref_name, *ref_version;
	enum razor_property_type type;

	if (ctx->package_iterator != NULL) {
		if (razor_package_iterator_next(ctx->package_iterator,
						&package,
						&name, &version)) {
			fprintf(stderr, "too few packages in set\n");
			exit(-1);
		}
				
		razor_package_iterator_destroy(ctx->package_iterator);
		ctx->package_iterator = NULL;
	}

	if (ctx->property_iterator != NULL) {
		if (razor_property_iterator_next(ctx->property_iterator,
						 &property,
						 &name, &version, &type)) {
			fprintf(stderr, "too few properties in set\n");
			exit(-1);
		}

		razor_property_iterator_destroy(ctx->property_iterator);
		ctx->property_iterator = NULL;
	}
}

static void
verify_package(struct test_context *ctx, const char **atts)
{
	struct razor_package *package;
	const char *name, *version, *ref_name, *ref_version;

	if (ctx->package_iterator == NULL) {
		fprintf(stderr,
			"\"package\" element seen, "
			"but not in package verify mode\n");
		exit(-1);
	}

	get_atts(atts, "name", &ref_name, "version", &ref_version, NULL);
	if (!razor_package_iterator_next(ctx->package_iterator,
					 &package, &name, &version)) {
		fprintf(stderr, "too many packages in set\n");
		exit(-1);
	}
			
	if (strcmp(name, ref_name) != 0 || strcmp(version, ref_version) != 0) {
		fprintf(stderr,
			"package mismatch; expected %s-%s, got %s-%s\n",
			ref_name, ref_version, name, version);
		exit(-1);
	}
}

static void
verify_property(struct test_context *ctx,
		enum razor_property_type ref_type, const char **atts)
{
	struct razor_property *property;
	const char *name, *version, *ref_name, *ref_version;
	enum razor_property_type type;
	int same_version;

	if (ctx->property_iterator == NULL) {
		fprintf(stderr,
			"\"requires/provides\" element seen, "
			"but not in property verify mode\n");
		exit(-1);
	}

	get_atts(atts, "name", &ref_name, "eq", &ref_version, NULL);
	if (!razor_property_iterator_next(ctx->property_iterator, &property,
					  &name, &version, &type)) {
		fprintf(stderr, "too many properties in set\n");
		exit(-1);
	}
			
	if (version != NULL && ref_version != NULL)
		same_version = strcmp(version, ref_version) == 0;
	else if (version == NULL && ref_version == NULL)
		same_version = 1;
	else
		same_version = 0;

	if (strcmp(name, ref_name) != 0 || !same_version || type != ref_type) {
		fprintf(stderr,
			"property mismatch; expected %s-%s/%d, got %s-%s/%d\n",
			ref_name, ref_version, ref_type,
			name, version, type);
		exit(-1);
	}
}

static void
start_test_element(void *data, const char *element, const char **atts)
{
	struct test_context *ctx = data;
	struct razor_set *set;
	const char *name;

	if (strcmp(element, "import") == 0) {
		get_atts(atts, "file", &name, NULL);
		parse_xml_file(name, start_set_element, end_set_element, ctx);
	} else if (strcmp(element, "update") == 0) {
		/* run update to create new set */
	} else if (strcmp(element, "verify") == 0) {
		verify_begin(ctx, atts);
	} else if (strcmp(element, "package") == 0) {
		verify_package(ctx, atts);
	} else if (strcmp(element, "requires") == 0) {
		verify_property(ctx, RAZOR_PROPERTY_REQUIRES, atts);
	} else if (strcmp(element, "provides") == 0) {
		verify_property(ctx, RAZOR_PROPERTY_PROVIDES, atts);
	} else if (strcmp(element, "conflicts") == 0) {
		verify_property(ctx, RAZOR_PROPERTY_CONFLICTS, atts);
	} else if (strcmp(element, "obsoletes") == 0) {
		verify_property(ctx, RAZOR_PROPERTY_OBSOLETES, atts);
	}
}

static void
end_test_element (void *data, const char *element)
{
	struct test_context *ctx = data;

	if (strcmp(element, "verify") == 0)
		verify_end(ctx);
}

int main(int argc, char *argv[])
{
	struct test_context ctx;
	struct test_set *set;

	if (argc != 2) {
		fprintf(stderr, "usage: %s TESTS-FILE\n", argv[0]);
		exit(-1);			
	}

	memset(&ctx, 0, sizeof ctx);
	parse_xml_file(argv[1], start_test_element, end_test_element, &ctx);

	return 0;
}
