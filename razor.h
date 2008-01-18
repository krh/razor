#ifndef _RAZOR_H_
#define _RAZOR_H_

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct razor_set;
struct razor_package;
struct razor_property;

enum razor_property_type {
	RAZOR_PROPERTY_REQUIRES,
	RAZOR_PROPERTY_PROVIDES,
	RAZOR_PROPERTY_CONFLICTS,
	RAZOR_PROPERTY_OBSOLETES
};

struct razor_set *razor_set_create(void);
struct razor_set *razor_set_open(const char *filename);
void razor_set_destroy(struct razor_set *set);
int razor_set_write(struct razor_set *set, const char *filename);

struct razor_package *
razor_set_get_package(struct razor_set *set, const char *package);

struct razor_package_iterator;
struct razor_package_iterator *
razor_package_iterator_create(struct razor_set *set);
struct razor_package_iterator *
razor_package_iterator_create_for_property(struct razor_set *set,
					   struct razor_property *property);
struct razor_package_iterator *
razor_package_iterator_create_for_file(struct razor_set *set,
				       const char *filename);

int razor_package_iterator_next(struct razor_package_iterator *pi,
				struct razor_package **package,
				const char **name, const char **version);
void razor_package_iterator_destroy(struct razor_package_iterator *pi);

struct razor_property_iterator;
struct razor_property_iterator *
razor_property_iterator_create(struct razor_set *set,
			       struct razor_package *package);
int razor_property_iterator_next(struct razor_property_iterator *pi,
				 struct razor_property **property,
				 const char **name, const char **version,
				 enum razor_property_type *type);
void
razor_property_iterator_destroy(struct razor_property_iterator *pi);

void razor_set_list_files(struct razor_set *set, const char *prefix);
void razor_set_list_package_files(struct razor_set *set, const char *name);

void razor_set_list_unsatisfied(struct razor_set *set);
struct razor_set *razor_set_update(struct razor_set *set,
				   struct razor_set *upstream,
				   int count, const char **packages);

typedef void (*razor_package_callback_t)(const char *name,
					 const char *old_version,
					 const char *new_version,
					 void *data);
void
razor_set_diff(struct razor_set *set, struct razor_set *upstream,
	       razor_package_callback_t callback, void *data);


/* Importer interface; for building a razor set from external sources,
 * like yum, rpmdb or razor package files. */

struct razor_importer;
struct razor_rpm;

struct razor_importer *razor_importer_new(void);
void razor_importer_destroy(struct razor_importer *importer);
void razor_importer_begin_package(struct razor_importer *importer,
				const char *name, const char *version);
void razor_importer_add_property(struct razor_importer *importer,
				 const char *name, const char *version,
				 enum razor_property_type type);
void razor_importer_add_file(struct razor_importer *importer,
			     const char *name);
void razor_importer_finish_package(struct razor_importer *importer);

int razor_importer_add_rpm(struct razor_importer *importer,
			   struct razor_rpm *rpm);

struct razor_set *razor_importer_finish(struct razor_importer *importer);

struct razor_set *razor_set_create_from_yum(void);
struct razor_set *razor_set_create_from_rpmdb(void);

/* RPM functions */

struct razor_rpm *razor_rpm_open(const char *filename);
int razor_rpm_install(struct razor_rpm *rpm, const char *root);
int razor_rpm_close(struct razor_rpm *rpm);

#endif /* _RAZOR_H_ */
