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
	RAZOR_PACKAGE_INSTALL,
	RAZOR_PACKAGE_FORCED_UPDATE,
	RAZOR_PACKAGE_REMOVE,
	RAZOR_PACKAGE_OBSOLETED,

	/* Error states */

	RAZOR_PACKAGE_FIRST_ERROR_STATE = 0x4,
	RAZOR_PACKAGE_UNAVAILABLE_FLAG = 0x4,

	/* Package requested for install does not exist */
	RAZOR_PACKAGE_INSTALL_UNAVAILABLE = RAZOR_PACKAGE_INSTALL | RAZOR_PACKAGE_UNAVAILABLE_FLAG,
	/* Package requiring update does not have any update */
	RAZOR_PACKAGE_UPDATE_UNAVAILABLE = RAZOR_PACKAGE_FORCED_UPDATE | RAZOR_PACKAGE_UNAVAILABLE_FLAG,
	/* Package requested for removal does not exist */
	RAZOR_PACKAGE_REMOVE_NOT_INSTALLED = RAZOR_PACKAGE_REMOVE | RAZOR_PACKAGE_UNAVAILABLE_FLAG,
	/* (not used) */
	RAZOR_PACKAGE_OBSOLETE_UNAVAILABLE = RAZOR_PACKAGE_OBSOLETED | RAZOR_PACKAGE_UNAVAILABLE_FLAG,

	/* No newer version of package is available */
	RAZOR_PACKAGE_UP_TO_DATE,
	/* Package marked for both install and remove */
	RAZOR_PACKAGE_CONTRADICTION,
	/* Package would add a conflict with an already-installed package */
	RAZOR_PACKAGE_NEW_CONFLICT,
	/* Already-installed package has a conflict against this package */
	RAZOR_PACKAGE_OLD_CONFLICT,
	/* Requirement of to-be-installed package can't be satisfied */
	RAZOR_PACKAGE_UNSATISFIABLE,
};

struct razor_transaction_package {
	const char *name, *old_version, *new_version;
	struct razor_package *old_package, *new_package;
	enum razor_transaction_package_state state;

	/* dep_package is the name of the package that resulted in
	 * this entry being created (or NULL if the user requested the
	 * install/remove), with the other dep_ fields providing
	 * additional information.
	 *
	 * For INSTALL, if dep_type is REQUIRES, then dep_package
	 * required something that this package provides. If dep_type
	 * is CONFLICTS, then dep_package is a package that conflicted
	 * with an older version of this package, forcing an upgrade.
	 *
	 * For REMOVE, if dep_type is REQUIRES, then dep_package is a
	 * package that is being removed. If dep_type is OBSOLETES,
	 * then dep_package is a package that obsoletes this one.
	 *
	 * For OLD_CONFLICT or NEW_CONFLICT, dep_package is an
	 * existing package that conflicts with this one. The
	 * conflicting property comes from the already-installed
	 * package for OLD_CONFLICT, or the to-be-installed package
	 * for NEW_CONFLICT.
	 *
	 * For UNSATISFIABLE, the dep_ fields are as for an INSTALL,
	 * but the name field will be NULL.
	 */
	const char *dep_package;
	enum razor_property_type dep_type;
	const char *dep_property;
	enum razor_version_relation dep_relation;
	const char *dep_version;
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

void razor_build_evr(char *evr_buf, int size, const char *epoch,
		     const char *version, const char *release);

struct razor_set *razor_set_create_from_yum(void);
struct razor_set *razor_set_create_from_rpmdb(void);

/* RPM functions */

struct razor_rpm *razor_rpm_open(const char *filename);
int razor_rpm_install(struct razor_rpm *rpm, const char *root);
int razor_rpm_close(struct razor_rpm *rpm);

#endif /* _RAZOR_H_ */
