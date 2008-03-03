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

enum razor_version_relation {
	RAZOR_VERSION_LESS,
	RAZOR_VERSION_LESS_OR_EQUAL,
	RAZOR_VERSION_EQUAL,
	RAZOR_VERSION_GREATER_OR_EQUAL,
	RAZOR_VERSION_GREATER
};
extern const char * const razor_version_relations[];

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
				 const char **name,
				 enum razor_version_relation *relation,
				 const char **version,
				 enum razor_property_type *type);
void
razor_property_iterator_destroy(struct razor_property_iterator *pi);

void razor_set_list_files(struct razor_set *set, const char *prefix);
void razor_set_list_package_files(struct razor_set *set, const char *name);

void razor_set_list_unsatisfied(struct razor_set *set);

typedef void (*razor_package_callback_t)(const char *name,
					 const char *old_version,
					 const char *new_version,
					 void *data);
void
razor_set_diff(struct razor_set *set, struct razor_set *upstream,
	       razor_package_callback_t callback, void *data);

/* Package transactions */

enum razor_transaction_package_state {
	/* Basic states */
	RAZOR_PACKAGE_INSTALL       = 0x01,
	RAZOR_PACKAGE_REMOVE        = 0x02,

	/* (Flags used to define the error states) */
	RAZOR_PACKAGE_UNAVAILABLE   = 0x04,
	RAZOR_PACKAGE_UNSATISFIABLE = 0x08,
	RAZOR_PACKAGE_BLOCKED       = 0x10,
	RAZOR_PACKAGE_CONFLICT      = 0x20,

	/* Error states */
	RAZOR_PACKAGE_INSTALL_UNAVAILABLE   = RAZOR_PACKAGE_INSTALL | RAZOR_PACKAGE_UNAVAILABLE,
	RAZOR_PACKAGE_INSTALL_UNSATISFIABLE = RAZOR_PACKAGE_INSTALL | RAZOR_PACKAGE_UNSATISFIABLE,
	RAZOR_PACKAGE_INSTALL_CONFLICT = RAZOR_PACKAGE_INSTALL | RAZOR_PACKAGE_CONFLICT,
	RAZOR_PACKAGE_REMOVE_NOT_INSTALLED  = RAZOR_PACKAGE_REMOVE | RAZOR_PACKAGE_UNAVAILABLE,
	RAZOR_PACKAGE_REMOVE_BLOCKED  = RAZOR_PACKAGE_REMOVE | RAZOR_PACKAGE_BLOCKED,
	RAZOR_PACKAGE_REMOVE_CONFLICT  = RAZOR_PACKAGE_REMOVE | RAZOR_PACKAGE_CONFLICT
};

struct razor_transaction_package {
	struct razor_package *package;
	const char *name, *version;
	enum razor_transaction_package_state state;

	const char *req_package;
	enum razor_property_type req_type;
	const char *req_property;
	enum razor_version_relation req_relation;
	const char *req_version;
};

struct razor_transaction {
	int package_count, errors;
	struct razor_transaction_package *packages;

	struct razor_set *system, *upstream;
};

struct razor_transaction *
razor_transaction_create(struct razor_set *system, struct razor_set *upstream,
			 int update_count, const char **update_packages,
			 int remove_count, const char **remove_packages);
void razor_transaction_describe(struct razor_transaction *trans);
struct razor_set *razor_transaction_run(struct razor_transaction *trans);
void razor_transaction_destroy(struct razor_transaction *trans);

/* Importer interface; for building a razor set from external sources,
 * like yum, rpmdb or razor package files. */

struct razor_importer;
struct razor_rpm;

struct razor_importer *razor_importer_new(void);
void razor_importer_destroy(struct razor_importer *importer);
void razor_importer_begin_package(struct razor_importer *importer,
				const char *name, const char *version);
void razor_importer_add_property(struct razor_importer *importer,
				 const char *name,
				 enum razor_version_relation relation,
				 const char *version,
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
