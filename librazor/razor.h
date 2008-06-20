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

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct razor_set;
struct razor_package;
struct razor_property;

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

const char *
razor_property_relation_to_string(struct razor_property *p);
const char *
razor_property_type_to_string(struct razor_property *p);

struct razor_set *razor_set_create(void);
struct razor_set *razor_set_open(const char *filename);
void razor_set_destroy(struct razor_set *set);
int razor_set_write_to_fd(struct razor_set *set, int fd);
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
				const char **name,
				const char **version,
				const char **arch);
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
void razor_set_list_package_files(struct razor_set *set, const char *name);

void razor_set_list_unsatisfied(struct razor_set *set);

typedef void (*razor_package_callback_t)(const char *name,
					 const char *old_version,
					 const char *new_version,
					 const char *arch,
					 void *data);
void
razor_set_diff(struct razor_set *set, struct razor_set *upstream,
	       razor_package_callback_t callback, void *data);

/* Package transactions */

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

/* Importer interface; for building a razor set from external sources,
 * like yum, rpmdb or razor package files. */

struct razor_importer;
struct razor_rpm;

struct razor_importer *razor_importer_new(void);
void razor_importer_destroy(struct razor_importer *importer);
void razor_importer_begin_package(struct razor_importer *importer,
				  const char *name,
				  const char *version,
				  const char *arch);
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

void razor_build_evr(char *evr_buf, int size, const char *epoch,
		     const char *version, const char *release);
int razor_versioncmp(const char *s1, const char *s2);

struct razor_set *razor_set_create_from_yum(void);
struct razor_set *razor_set_create_from_rpmdb(void);

/* RPM functions */

struct razor_rpm *razor_rpm_open(const char *filename);
int razor_rpm_install(struct razor_rpm *rpm, const char *root);
int razor_rpm_close(struct razor_rpm *rpm);


/* Razor root functions. The root data struct encapsulates filesystem
 * conventions and the locking protocol. */

struct razor_root;
#define RAZOR_ROOT_OPEN_WRITE 0x01

int razor_root_create(const char *root);
struct razor_root *razor_root_open(const char *root, int flags);
struct razor_set *razor_root_open_read_only(const char *root);
struct razor_transaction *
razor_root_create_transaction(struct razor_root *image,
			      struct razor_set *upstream);
int razor_root_close(struct razor_root *image);
void razor_root_update(struct razor_root *image, struct razor_set *next);
int razor_root_commit(struct razor_root *image);
void razor_root_diff(struct razor_root *root,
		     razor_package_callback_t callback, void *data);

#endif /* _RAZOR_H_ */
