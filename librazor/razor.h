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

#ifndef _RAZOR_H_
#define _RAZOR_H_

#include <stdint.h>

enum razor_repo_file_type {
	RAZOR_REPO_FILE_MAIN,
	RAZOR_REPO_FILE_DETAILS,
	RAZOR_REPO_FILE_FILES
};

enum razor_detail_type {
	RAZOR_DETAIL_LAST = 0,	/* the sentinel */
	RAZOR_DETAIL_NAME,
	RAZOR_DETAIL_VERSION,
	RAZOR_DETAIL_ARCH,
	RAZOR_DETAIL_SUMMARY,
	RAZOR_DETAIL_DESCRIPTION,
	RAZOR_DETAIL_URL,
	RAZOR_DETAIL_LICENSE
};

enum razor_property_flags {
	RAZOR_PROPERTY_LESS		= 1 << 0,
	RAZOR_PROPERTY_GREATER		= 1 << 1,
	RAZOR_PROPERTY_EQUAL		= 1 << 2,
	RAZOR_PROPERTY_RELATION_MASK	=
		RAZOR_PROPERTY_LESS |
		RAZOR_PROPERTY_GREATER |
		RAZOR_PROPERTY_EQUAL,

	RAZOR_PROPERTY_REQUIRES		= 0 << 3,
	RAZOR_PROPERTY_PROVIDES		= 1 << 3,
	RAZOR_PROPERTY_CONFLICTS	= 2 << 3,
	RAZOR_PROPERTY_OBSOLETES	= 3 << 3,
	RAZOR_PROPERTY_TYPE_MASK	= 3 << 3,
		
	RAZOR_PROPERTY_PRE		= 1 << 5,
	RAZOR_PROPERTY_POST		= 1 << 6,
	RAZOR_PROPERTY_PREUN		= 1 << 7,
	RAZOR_PROPERTY_POSTUN		= 1 << 8
};

/**
 * SECTION:set
 * @title: Package Set
 * @short_description: Represents a set of packages and their metadata.
 *
 * This object represents a set of packages, their dependency
 * information, the file lists and a number of other details.
 **/

struct razor_set;
struct razor_package;
struct razor_property;

/**
 * razor_set_create:
 * 
 * Create a new #razor_set object.
 * 
 * Returns: the new #razor_set object.
 **/
struct razor_set *razor_set_create(void);
struct razor_set *razor_set_open(const char *filename);
void razor_set_destroy(struct razor_set *set);
int razor_set_write_to_fd(struct razor_set *set, int fd,
			  enum razor_repo_file_type type);
int razor_set_write(struct razor_set *set, const char *filename,
		    enum razor_repo_file_type type);

int razor_set_open_details(struct razor_set *set, const char *filename);
int razor_set_open_files(struct razor_set *set, const char *filename);

struct razor_package *
razor_set_get_package(struct razor_set *set, const char *package);

void
razor_package_get_details(struct razor_set *set,
			  struct razor_package *package, ...);


/**
 * SECTION:iterator
 * @title: Iterators
 * @short_description: Objects for traversing packages or properties.
 *
 * The razor iterator objects provides a way to iterate through a set
 * of packages or properties.
 **/

struct razor_package_iterator;

/**
 * razor_package_iterator_create:
 * 
 * Create a new #razor_package_iterator object.
 * 
 * Returns: the new #razor_package_iterator object.
 **/

struct razor_package_iterator *
razor_package_iterator_create(struct razor_set *set);

/**
 * razor_package_iterator_create_for_property:
 * 
 * Create a new #razor_package_iterator object for the packages that
 * own the given property.
 * 
 * Returns: the new #razor_package_iterator object.
 **/
struct razor_package_iterator *
razor_package_iterator_create_for_property(struct razor_set *set,
					   struct razor_property *property);

/**
 * razor_package_iterator_create_for_file:
 *
 * Create a new #razor_package_iterator object for the packages that
 * contain the given file name.
 *
 * Returns: the new #razor_package_iterator object.
 **/
struct razor_package_iterator *
razor_package_iterator_create_for_file(struct razor_set *set,
				       const char *filename);

int razor_package_iterator_next(struct razor_package_iterator *pi,
				struct razor_package **package, ...);
void razor_package_iterator_destroy(struct razor_package_iterator *pi);

struct razor_package_query *
razor_package_query_create(struct razor_set *set);
void
razor_package_query_add_package(struct razor_package_query *pq,
				struct razor_package *p);
void
razor_package_query_add_iterator(struct razor_package_query *pq,
				 struct razor_package_iterator *pi);
struct razor_package_iterator *
razor_package_query_finish(struct razor_package_query *pq);

struct razor_property_iterator;
struct razor_property_iterator *
razor_property_iterator_create(struct razor_set *set,
			       struct razor_package *package);
int razor_property_iterator_next(struct razor_property_iterator *pi,
				 struct razor_property **property,
				 const char **name,
				 uint32_t *flags,
				 const char **version);
void
razor_property_iterator_destroy(struct razor_property_iterator *pi);

void razor_set_list_files(struct razor_set *set, const char *prefix);
void razor_set_list_package_files(struct razor_set *set,
				  struct razor_package *package);

enum razor_diff_action {
	RAZOR_DIFF_ACTION_ADD,
	RAZOR_DIFF_ACTION_REMOVE,
};

typedef void (*razor_diff_callback_t)(enum razor_diff_action action,
				      struct razor_package *package,
				      const char *name,
				      const char *version,
				      const char *arch,
				      void *data);

void
razor_set_diff(struct razor_set *set, struct razor_set *upstream,
	       razor_diff_callback_t callback, void *data);
struct razor_package_iterator *
razor_set_create_remove_iterator(struct razor_set *set,
				 struct razor_set *next);
struct razor_package_iterator *
razor_set_create_install_iterator(struct razor_set *set,
				  struct razor_set *next);

/**
 * SECTION:transaction
 * @title: Transaction
 * @short_description: Create a new package set by merging two or more sets.
 *
 * The razor transaction object provides a way to create a new package set
 * from packages from one or more other package sets.
 **/

struct razor_transaction *
razor_transaction_create(struct razor_set *system, struct razor_set *upstream);
void razor_transaction_install_package(struct razor_transaction *transaction,
				       struct razor_package *package);
void razor_transaction_remove_package(struct razor_transaction *transaction,
				      struct razor_package *package);
void razor_transaction_update_package(struct razor_transaction *trans,
				      struct razor_package *package);
void razor_transaction_update_all(struct razor_transaction *transaction);
int razor_transaction_resolve(struct razor_transaction *trans);
int razor_transaction_describe(struct razor_transaction *trans);
struct razor_set *razor_transaction_finish(struct razor_transaction *trans);
void razor_transaction_destroy(struct razor_transaction *trans);

/* Temporary helper for test suite. */
int razor_transaction_unsatisfied_property(struct razor_transaction *trans,
					   const char *name,
					   uint32_t flags,
					   const char *version);

/**
 * SECTION:rpm
 * @title: Razor RPM
 * @short_description: Operating on RPM files.
 *
 * Functions for open RPM files and extracting information and
 * installing or removing RPM files.
 **/

struct razor_rpm;

struct razor_rpm *razor_rpm_open(const char *filename);
int razor_rpm_install(struct razor_rpm *rpm, const char *root);
int razor_rpm_close(struct razor_rpm *rpm);

/**
 * SECTION:importer
 * @title: Importer
 * @short_description: A mechanism for building #razor_set objects
 *
 * The %razor_importer is a helper object for building a razor set
 * from external sources, like yum metadata, the RPM database or RPM
 * files.
 *
 * The importer is a stateful object; it has the notion of a current
 * package, and the caller can provide meta data such as properties,
 * files and similiar for the package as it becomes available.  Once a
 * package is fully described, the next pacakge can begin.  When all
 * packages have been described to the importer, the importer will
 * create a new %razor_set with the specified packages.
 *
 * A typical use
 * of the importer will follow this template:
 * |[
 * importer = razor_importer_create();
 *
 * while ( /<!-- -->* more packages to import *<!-- -->/; ) {
 *   /<!-- -->* get name, version and arch of next package *<!-- -->/
 *   razor_importer_begin_package(importer, name, version, arch);
 *   razor_importer_add_details(importer, summary, description, url, license);
 *
 *   while ( /<!-- -->* more properties to add *<!-- -->/ )
 *     razor_importer_add_property(importer, name, flags, version);
 *
 *   while ( /<!-- -->* [more files to add *<!-- -->/ )
 *     razor_importer_add_file(importer, name);
 *
 *   razor_importer_finish_package(importer);
 * }
 *
 * return razor_importer_finish(importer);
 * ]|
 **/
struct razor_importer;

struct razor_importer *razor_importer_create(void);
void razor_importer_destroy(struct razor_importer *importer);
void razor_importer_begin_package(struct razor_importer *importer,
				  const char *name,
				  const char *version,
				  const char *arch);
void razor_importer_add_details(struct razor_importer *importer,
				const char *summary,
				const char *description,
				const char *url,
				const char *license);
void razor_importer_add_property(struct razor_importer *importer,
				 const char *name,
				 uint32_t flags,
				 const char *version);
void razor_importer_add_file(struct razor_importer *importer,
			     const char *name);
void razor_importer_finish_package(struct razor_importer *importer);

int razor_importer_add_rpm(struct razor_importer *importer,
			   struct razor_rpm *rpm);

struct razor_set *razor_importer_finish(struct razor_importer *importer);

struct razor_set *razor_set_create_from_yum(void);
struct razor_set *razor_set_create_from_rpmdb(void);

/**
 * SECTION:root
 * @title: Root
 * @short_description: Functions for accessing an install root.
 *
 * The #razor_root object encapsulate access to and locking of a razor
 * install root.
 **/
struct razor_root;

int razor_root_create(const char *root);
struct razor_root *razor_root_open(const char *root);
struct razor_set *razor_root_open_read_only(const char *root);
struct razor_set *razor_root_get_system_set(struct razor_root *root);
int razor_root_close(struct razor_root *root);
void razor_root_update(struct razor_root *root, struct razor_set *next);
int razor_root_commit(struct razor_root *root);


/**
 * SECTION:misc
 * @title: Miscellaneous Functions
 * @short_description: Various helper functions
 *
 * Functions that doesn't fit anywhere else.
 **/

const char *
razor_property_relation_to_string(struct razor_property *p);
const char *
razor_property_type_to_string(struct razor_property *p);

void razor_build_evr(char *evr_buf, int size, const char *epoch,
		     const char *version, const char *release);
int razor_versioncmp(const char *s1, const char *s2);


#endif /* _RAZOR_H_ */
