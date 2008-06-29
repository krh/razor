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

#define _GNU_SOURCE

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <fnmatch.h>
#include <assert.h>

#include "razor-internal.h"
#include "razor.h"

static int
provider_satisfies_requirement(struct razor_property *provider,
			       const char *provider_strings,
			       uint32_t flags,
			       const char *required)
{
	int cmp, len;
	const char *provided = &provider_strings[provider->version];

	if (!*required)
		return 1;
	if (!*provided) {
		if (flags & RAZOR_PROPERTY_LESS)
			return 0;
		else
			return 1;
	}

	cmp = razor_versioncmp(provided, required);

	switch (flags & RAZOR_PROPERTY_RELATION_MASK) {
	case RAZOR_PROPERTY_LESS:
		return cmp < 0;

	case RAZOR_PROPERTY_LESS | RAZOR_PROPERTY_EQUAL:
		if (cmp <= 0)
			return 1;
		/* fall through: FIXME, make sure this is correct */

	case RAZOR_PROPERTY_EQUAL:
		if (cmp == 0)
			return 1;

		/* "foo == 1.1" is satisfied by "foo 1.1-2" */
		len = strlen(required);
		if (!strncmp(required, provided, len) && provided[len] == '-')
			return 1;
		return 0;

	case RAZOR_PROPERTY_GREATER | RAZOR_PROPERTY_EQUAL:
		return cmp >= 0;

	case RAZOR_PROPERTY_GREATER:
		return cmp > 0;
	}

	/* shouldn't happen */
	return 0;
}

#define TRANS_PACKAGE_PRESENT		1
#define TRANS_PACKAGE_UPDATE		2
#define TRANS_PROPERTY_SATISFIED	0x80000000

struct transaction_set {
	struct razor_set *set;
	uint32_t *packages;
	uint32_t *properties;
};

struct razor_transaction {
	int package_count, errors;
	struct transaction_set system, upstream;
	int changes;
};

static void
transaction_set_init(struct transaction_set *ts, struct razor_set *set)
{
	int count;

	ts->set = set;
	count = set->packages.size / sizeof (struct razor_package);
	ts->packages = zalloc(count * sizeof *ts->packages);
	count = set->properties.size / sizeof (struct razor_property);
	ts->properties = zalloc(count * sizeof *ts->properties);
}

static void
transaction_set_release(struct transaction_set *ts)
{
	free(ts->packages);
	free(ts->properties);
}

static void
transaction_set_install_package(struct transaction_set *ts,
				struct razor_package *package)
{
	struct razor_package *pkgs;
	struct list *prop;
	int i;

	pkgs = ts->set->packages.data;
	i = package - pkgs;
	if (ts->packages[i] == TRANS_PACKAGE_PRESENT)
		return;

	ts->packages[i] = TRANS_PACKAGE_PRESENT;

	prop = list_first(&package->properties, &ts->set->property_pool);
	while (prop) {
		ts->properties[prop->data]++;
		prop = list_next(prop);
	}
}

static void
transaction_set_remove_package(struct transaction_set *ts,
			       struct razor_package *package)
{
	struct razor_package *pkgs;
	struct list *prop;
	int i;

	pkgs = ts->set->packages.data;
	i = package - pkgs;
	if (ts->packages[i] == 0)
		return;

	ts->packages[i] = 0;

	prop = list_first(&package->properties, &ts->set->property_pool);
	while (prop) {
		ts->properties[prop->data]--;
		prop = list_next(prop);
	}
}

RAZOR_EXPORT struct razor_transaction *
razor_transaction_create(struct razor_set *system, struct razor_set *upstream)
{
	struct razor_transaction *trans;
	struct razor_package *p, *spkgs, *pend;

	trans = zalloc(sizeof *trans);
	transaction_set_init(&trans->system, system);
	transaction_set_init(&trans->upstream, upstream);

	spkgs = trans->system.set->packages.data;
	pend = trans->system.set->packages.data +
		trans->system.set->packages.size;
	for (p = spkgs; p < pend; p++)
		transaction_set_install_package(&trans->system, p);

	return trans;
}

RAZOR_EXPORT void
razor_transaction_install_package(struct razor_transaction *trans,
				  struct razor_package *package)
{
	assert (trans != NULL);
	assert (package != NULL);

	transaction_set_install_package(&trans->upstream, package);
	trans->changes++;
}

RAZOR_EXPORT void
razor_transaction_remove_package(struct razor_transaction *trans,
				 struct razor_package *package)
{
	assert (trans != NULL);
	assert (package != NULL);

	transaction_set_remove_package(&trans->system, package);
	trans->changes++;
}

RAZOR_EXPORT void
razor_transaction_update_package(struct razor_transaction *trans,
				  struct razor_package *package)
{
	struct razor_package *spkgs, *upkgs, *end;

	assert (trans != NULL);
	assert (package != NULL);

	spkgs = trans->system.set->packages.data;
	upkgs = trans->upstream.set->packages.data;
	end = trans->system.set->packages.data +
		trans->system.set->packages.size;
	if (spkgs <= package && package < end)
		trans->system.packages[package - spkgs] |= TRANS_PACKAGE_UPDATE;
	else
		trans->upstream.packages[package - upkgs] |= TRANS_PACKAGE_UPDATE;
}

struct prop_iter {
	struct razor_property *p, *start, *end;
	const char *pool;
	uint32_t *present;
};

static void
prop_iter_init(struct prop_iter *pi, struct transaction_set *ts)
{
	pi->p = ts->set->properties.data;
	pi->start = ts->set->properties.data;
	pi->end = ts->set->properties.data + ts->set->properties.size;
	pi->pool = ts->set->string_pool.data;
	pi->present = ts->properties;
}

static int
prop_iter_next(struct prop_iter *pi, uint32_t flags, struct razor_property **p)
{
	while (pi->p < pi->end) {
		if ((pi->present[pi->p - pi->start] & ~TRANS_PROPERTY_SATISFIED) &&
		    (pi->p->flags & RAZOR_PROPERTY_TYPE_MASK) == flags) {
			*p = pi->p++;
			return 1;
		}
		pi->p++;
	}

	return 0;
}

static struct razor_property *
prop_iter_seek_to(struct prop_iter *pi,
		  uint32_t flags, const char *match)
{
	uint32_t name;

	while (pi->p < pi->end && strcmp(&pi->pool[pi->p->name], match) < 0)
		pi->p++;

	if (pi->p == pi->end || strcmp(&pi->pool[pi->p->name], match) > 0)
		return NULL;

	name = pi->p->name;
	while (pi->p < pi->end &&
	       pi->p->name == name &&
	       (pi->p->flags & RAZOR_PROPERTY_TYPE_MASK) != flags)
		pi->p++;

	if (pi->p == pi->end || pi->p->name != name)
		return NULL;

	return pi->p;
}

/* Remove packages from set that provide any of the matching (same
 * name and type) providers from ppi onwards that match the
 * requirement that rpi points to. */
static void
remove_matching_providers(struct razor_transaction *trans,
			  struct prop_iter *ppi,
			  uint32_t flags,
			  const char *version)
{
	struct razor_property *p;
	struct razor_package *pkg, *pkgs;
	struct razor_package_iterator pkg_iter;
	struct razor_set *set;
	const char *n, *v, *a;
	uint32_t type;

	if (ppi->present == trans->system.properties)
		set = trans->system.set;
	else
		set = trans->upstream.set;

	pkgs = (struct razor_package *) set->packages.data;
	type = ppi->p->flags & RAZOR_PROPERTY_TYPE_MASK;
	for (p = ppi->p;
	     p < ppi->end &&
	     p->name == ppi->p->name &&
	     (p->flags & RAZOR_PROPERTY_TYPE_MASK) == type;
	     p++) {
		if (!ppi->present[p - ppi->start])
			continue;
		if (!provider_satisfies_requirement(p, ppi->pool,
						    flags, version))
			continue;

		razor_package_iterator_init_for_property(&pkg_iter, set, p);
		while (razor_package_iterator_next(&pkg_iter,
						   &pkg, &n, &v, &a)) {
			fprintf(stderr, "removing %s-%s\n", n, v);
			razor_transaction_remove_package(trans, pkg);
		}
	}
}

static void
flag_matching_providers(struct razor_transaction *trans,
			struct prop_iter *ppi,
			struct razor_property *r,
			struct prop_iter *rpi,
			unsigned int flag)
{
	struct razor_property *p;
	struct razor_package *pkg, *pkgs;
	struct razor_package_iterator pkg_iter;
	struct razor_set *set;
	const char *name, *version, *arch;
	uint32_t *flags, type;

	if (ppi->present == trans->system.properties) {
		set = trans->system.set;
		flags = trans->system.packages;
	} else {
		set = trans->upstream.set;
		flags = trans->upstream.packages;
	}

	pkgs = (struct razor_package *) set->packages.data;
	type = ppi->p->flags & RAZOR_PROPERTY_TYPE_MASK;
	for (p = ppi->p;
	     p < ppi->end &&
		     p->name == ppi->p->name &&
		     (p->flags & RAZOR_PROPERTY_TYPE_MASK) == type;
	     p++) {
		if (!ppi->present[p - ppi->start])
			continue;
		if (!provider_satisfies_requirement(p, ppi->pool,
						    r->flags,
						    &rpi->pool[r->version]))
			continue;

		razor_package_iterator_init_for_property(&pkg_iter, set, p);
		while (razor_package_iterator_next(&pkg_iter, &pkg,
						   &name, &version, &arch)) {

			fprintf(stderr, "flagging %s-%s for providing %s matching %s %s\n",
				name, version,
				ppi->pool + p->name,
				rpi->pool + r->name,
				rpi->pool + r->version);
			flags[pkg - pkgs] |= flag;
		}
	}
}

static struct razor_package *
pick_matching_provider(struct razor_set *set,
		       struct prop_iter *ppi,
		       uint32_t flags,
		       const char *version)
{
	struct razor_property *p;
	struct razor_package *pkgs;
	struct list *i;
	uint32_t type;

	/* This is where we decide which pkgs to pull in to satisfy a
	 * requirement.  There may be several different providers
	 * (different versions) and each version of a provider may
	 * come from a number of packages.  We pick the first package
	 * from the first provider that matches. */

	pkgs = set->packages.data;
	type = ppi->p->flags & RAZOR_PROPERTY_TYPE_MASK;
	for (p = ppi->p;
	     p < ppi->end &&
		     p->name == ppi->p->name &&
		     (p->flags & RAZOR_PROPERTY_TYPE_MASK) == type &&
		     ppi->present[p - ppi->start] == 0;
	     p++) {
		if (!provider_satisfies_requirement(p, ppi->pool,
						    flags, version))
			continue;

		i = list_first(&p->packages, &set->package_pool);

		return &pkgs[i->data];
	}

	return NULL;
}

static void
remove_obsoleted_packages(struct razor_transaction *trans)
{
	struct razor_property *up;
	struct razor_package *spkgs;
	struct prop_iter spi, upi;

	spkgs = trans->system.set->packages.data;
	prop_iter_init(&spi, &trans->system);
	prop_iter_init(&upi, &trans->upstream);

	while (prop_iter_next(&upi, RAZOR_PROPERTY_OBSOLETES, &up)) {
		if (!prop_iter_seek_to(&spi, RAZOR_PROPERTY_PROVIDES,
				       &upi.pool[up->name]))
			continue;
		remove_matching_providers(trans, &spi, up->flags,
					  &upi.pool[up->version]);
	}
}

static int
any_provider_satisfies_requirement(struct prop_iter *ppi,
				   uint32_t flags,
				   const char *version)
{
	struct razor_property *p;
	uint32_t type;

	type = ppi->p->flags & RAZOR_PROPERTY_TYPE_MASK;
	for (p = ppi->p;
	     p < ppi->end &&
		     p->name == ppi->p->name &&
		     (p->flags & RAZOR_PROPERTY_TYPE_MASK) == type;
	     p++) {
		if (ppi->present[p - ppi->start] > 0 &&
		    provider_satisfies_requirement(p, ppi->pool,
						   flags, version))
			return 1;
	}

	return 0;
}

static void
clear_requires_flags(struct transaction_set *ts)
{
	struct razor_property *p;
	const char *pool;
	int i, count;

	count = ts->set->properties.size / sizeof *p;
	p = ts->set->properties.data;
	pool = ts->set->string_pool.data;
	for (i = 0; i < count; i++) {
		ts->properties[i] &= ~TRANS_PROPERTY_SATISFIED;
		if (strncmp(&pool[p[i].name], "rpmlib(", 7) == 0)
			ts->properties[i] |= TRANS_PROPERTY_SATISFIED;
	}
}

static void
mark_satisfied_requires(struct razor_transaction *trans,
			struct transaction_set *rts,
			struct transaction_set *pts)
{
	struct prop_iter rpi, ppi;
	struct razor_property *rp;

	prop_iter_init(&rpi, rts);
	prop_iter_init(&ppi, pts);

	while (prop_iter_next(&rpi, RAZOR_PROPERTY_REQUIRES, &rp)) {
		if (!prop_iter_seek_to(&ppi, RAZOR_PROPERTY_PROVIDES,
				       &rpi.pool[rp->name]))
			continue;

		if (any_provider_satisfies_requirement(&ppi, rp->flags,
						       &rpi.pool[rp->version]))
			rpi.present[rp - rpi.start] |= TRANS_PROPERTY_SATISFIED;
	}
}

static void
mark_all_satisfied_requires(struct razor_transaction *trans)
{
	clear_requires_flags(&trans->system);
	clear_requires_flags(&trans->upstream);
	mark_satisfied_requires(trans, &trans->system, &trans->system);
	mark_satisfied_requires(trans, &trans->system, &trans->upstream);
	mark_satisfied_requires(trans, &trans->upstream, &trans->system);
	mark_satisfied_requires(trans, &trans->upstream, &trans->upstream);
}

static void
update_unsatisfied_packages(struct razor_transaction *trans)
{
	struct razor_package *spkgs, *pkg;
	struct razor_property *sp;
	struct prop_iter spi;
	struct razor_package_iterator pkg_iter;
	const char *name, *version, *arch;

	spkgs = trans->system.set->packages.data;
	prop_iter_init(&spi, &trans->system);

	while (prop_iter_next(&spi, RAZOR_PROPERTY_REQUIRES, &sp)) {
		if (spi.present[sp - spi.start] & TRANS_PROPERTY_SATISFIED)
			continue;

		razor_package_iterator_init_for_property(&pkg_iter,
							 trans->system.set,
							 sp);
		while (razor_package_iterator_next(&pkg_iter, &pkg,
						   &name, &version, &arch)) {
			fprintf(stderr, "updating %s because %s %s %s "
				"isn't satisfied\n",
				name, spi.pool + sp->name,
				razor_property_relation_to_string(sp),
				spi.pool + sp->version);
			trans->system.packages[pkg - spkgs] |=
				TRANS_PACKAGE_UPDATE;
		}
	}
}

RAZOR_EXPORT void
razor_transaction_update_all(struct razor_transaction *trans)
{
	struct razor_package *p;
	int i, count;

	assert (trans != NULL);

	count = trans->system.set->packages.size / sizeof *p;
	for (i = 0; i < count; i++)
		trans->system.packages[i] |= TRANS_PACKAGE_UPDATE;
}

static void
update_conflicted_packages(struct razor_transaction *trans)
{
	struct razor_package *pkg, *spkgs;
	struct razor_property *up, *sp;
	struct prop_iter spi, upi;
	struct razor_package_iterator pkg_iter;
	const char *name, *version, *arch;

	spkgs = trans->system.set->packages.data;
	prop_iter_init(&spi, &trans->system);
	prop_iter_init(&upi, &trans->upstream);

	while (prop_iter_next(&spi, RAZOR_PROPERTY_CONFLICTS, &sp)) {
		if (!prop_iter_seek_to(&upi, RAZOR_PROPERTY_PROVIDES,
				       &spi.pool[sp->name]))
			continue;

		if (!any_provider_satisfies_requirement(&upi, sp->flags,
							&spi.pool[sp->version]))
			continue;

		razor_package_iterator_init_for_property(&pkg_iter,
							 trans->system.set,
							 sp);
		while (razor_package_iterator_next(&pkg_iter, &pkg,
						   &name, &version, &arch)) {
			fprintf(stderr, "updating %s %s because it "
				"conflicts with %s\n",
				name, version, spi.pool + sp->name);
			trans->system.packages[pkg - spkgs] |=
				TRANS_PACKAGE_UPDATE;
		}
	}

	prop_iter_init(&spi, &trans->system);
	prop_iter_init(&upi, &trans->upstream);

	while (prop_iter_next(&upi, RAZOR_PROPERTY_CONFLICTS, &up)) {
		sp = prop_iter_seek_to(&spi, RAZOR_PROPERTY_PROVIDES,
				       &upi.pool[upi.p->name]);

		if (sp)
			flag_matching_providers(trans, &spi, up, &upi,
						TRANS_PACKAGE_UPDATE);
	}
}

static void
pull_in_requirements(struct razor_transaction *trans,
		     struct prop_iter *rpi, struct prop_iter *ppi)
{
	struct razor_property *rp, *pp;
	struct razor_package *pkg, *upkgs;

	upkgs = trans->upstream.set->packages.data;
	while (prop_iter_next(rpi, RAZOR_PROPERTY_REQUIRES, &rp)) {
		if (rpi->present[rp - rpi->start] & TRANS_PROPERTY_SATISFIED)
			continue;

		pp = prop_iter_seek_to(ppi, RAZOR_PROPERTY_PROVIDES,
				       &rpi->pool[rp->name]);
		if (pp == NULL)
			continue;
		pkg = pick_matching_provider(trans->upstream.set,
					     ppi, rp->flags,
					     &rpi->pool[rp->version]);
		if (pkg == NULL)
			continue;

		rpi->present[rp - rpi->start] |= TRANS_PROPERTY_SATISFIED;

		fprintf(stderr, "pulling in %s-%s.%s which provides %s %s %s "
			"to satisfy %s %s %s\n",
			ppi->pool + pkg->name,
			ppi->pool + pkg->version,
			ppi->pool + pkg->arch,
			ppi->pool + pp->name,
			razor_property_relation_to_string(pp),
			ppi->pool + pp->version,
			&rpi->pool[rp->name],
			razor_property_relation_to_string(rp),
			&rpi->pool[rp->version]);

		trans->upstream.packages[pkg - upkgs] |= TRANS_PACKAGE_UPDATE;
	}
}

static void
pull_in_all_requirements(struct razor_transaction *trans)
{
	struct prop_iter rpi, ppi;

	prop_iter_init(&rpi, &trans->system);
	prop_iter_init(&ppi, &trans->upstream);
	pull_in_requirements(trans, &rpi, &ppi);

	prop_iter_init(&rpi, &trans->upstream);
	prop_iter_init(&ppi, &trans->upstream);
	pull_in_requirements(trans, &rpi, &ppi);
}

static void
flush_scheduled_system_updates(struct razor_transaction *trans)
{
 	struct razor_package_iterator *pi;
 	struct razor_package *p, *pkg, *spkgs;
	struct prop_iter ppi;
	const char *name, *version, *arch;

	spkgs = trans->system.set->packages.data;
	pi = razor_package_iterator_create(trans->system.set);
	prop_iter_init(&ppi, &trans->upstream);

	while (razor_package_iterator_next(pi, &p, &name, &version, &arch)) {
		if (!(trans->system.packages[p - spkgs] & TRANS_PACKAGE_UPDATE))
			continue;

		if (!prop_iter_seek_to(&ppi, RAZOR_PROPERTY_PROVIDES, name))
			continue;

		pkg = pick_matching_provider(trans->upstream.set, &ppi,
					     RAZOR_PROPERTY_GREATER, version);
		if (pkg == NULL)
			continue;

		fprintf(stderr, "updating %s-%s to %s-%s\n",
			name, version,
			&ppi.pool[pkg->name], &ppi.pool[pkg->version]);

		razor_transaction_remove_package(trans, p);
		razor_transaction_install_package(trans, pkg);
	}

	razor_package_iterator_destroy(pi);
}

static void
flush_scheduled_upstream_updates(struct razor_transaction *trans)
{
 	struct razor_package_iterator *pi;
 	struct razor_package *p, *upkgs;
	struct prop_iter spi;
	const char *name, *version, *arch;

	upkgs = trans->upstream.set->packages.data;
	pi = razor_package_iterator_create(trans->upstream.set);
	prop_iter_init(&spi, &trans->system);

	while (razor_package_iterator_next(pi, &p, &name, &version, &arch)) {
		if (!(trans->upstream.packages[p - upkgs] & TRANS_PACKAGE_UPDATE))
			continue;

		if (prop_iter_seek_to(&spi, RAZOR_PROPERTY_PROVIDES, name))
			remove_matching_providers(trans,
						  &spi,
						  RAZOR_PROPERTY_LESS,
						  version);
		razor_transaction_install_package(trans, p);
		fprintf(stderr, "installing %s-%s\n", name, version);
	}
}

RAZOR_EXPORT int
razor_transaction_resolve(struct razor_transaction *trans)
{
	int last = 0;

	flush_scheduled_system_updates(trans);
	flush_scheduled_upstream_updates(trans);

	while (last < trans->changes) {
		last = trans->changes;
		remove_obsoleted_packages(trans);
		mark_all_satisfied_requires(trans);
		update_unsatisfied_packages(trans);
		update_conflicted_packages(trans);
		pull_in_all_requirements(trans);
		flush_scheduled_system_updates(trans);
		flush_scheduled_upstream_updates(trans);
	}

	return trans->changes;
}

static void
describe_unsatisfied(struct razor_set *set, struct razor_property *rp)
{
	struct razor_package_iterator pi;
	struct razor_package *pkg;
	const char *name, *version, *arch, *pool;

	pool = set->string_pool.data;
	if (pool[rp->version] == '\0') {
		razor_package_iterator_init_for_property(&pi, set, rp);
		while (razor_package_iterator_next(&pi, &pkg,
						   &name, &version, &arch))
			fprintf(stderr, "%s is needed by %s-%s.%s\n",
				&pool[rp->name],
				name, version, arch);
	} else {
		razor_package_iterator_init_for_property(&pi, set, rp);
		while (razor_package_iterator_next(&pi, &pkg,
						   &name, &version, &arch))
			fprintf(stderr, "%s %s %s is needed by %s-%s.%s\n",
				&pool[rp->name],
				razor_property_relation_to_string(rp),
				&pool[rp->version],
				name, version, arch);
	}
}

RAZOR_EXPORT int
razor_transaction_describe(struct razor_transaction *trans)
{
	struct prop_iter rpi;
	struct razor_property *rp;
	int unsatisfied;

	flush_scheduled_system_updates(trans);
	flush_scheduled_upstream_updates(trans);
	mark_all_satisfied_requires(trans);

	unsatisfied = 0;
	prop_iter_init(&rpi, &trans->system);
	while (prop_iter_next(&rpi, RAZOR_PROPERTY_REQUIRES, &rp)) {
		if (!(rpi.present[rp - rpi.start] & TRANS_PROPERTY_SATISFIED)) {
			describe_unsatisfied(trans->system.set, rp);
		        unsatisfied++;
		}
	}

	prop_iter_init(&rpi, &trans->upstream);
	while (prop_iter_next(&rpi, RAZOR_PROPERTY_REQUIRES, &rp)) {
		if (!(rpi.present[rp - rpi.start] & TRANS_PROPERTY_SATISFIED)) {
			describe_unsatisfied(trans->upstream.set, rp);
			unsatisfied++;
		}
	}

	return unsatisfied;
}

RAZOR_EXPORT int
razor_transaction_unsatisfied_property(struct razor_transaction *trans,
				       const char *name,
				       uint32_t flags,
				       const char *version)
{
	struct prop_iter pi;
	struct razor_property *p;

	prop_iter_init(&pi, &trans->system);
	while (prop_iter_next(&pi, flags & RAZOR_PROPERTY_TYPE_MASK, &p)) {
		if (!(trans->system.properties[p - pi.start] & TRANS_PROPERTY_SATISFIED) &&
		    p->flags == flags &&
		    strcmp(&pi.pool[p->name], name) == 0 &&
		    strcmp(&pi.pool[p->version], version) == 0)

			return 1;
	}

	prop_iter_init(&pi, &trans->upstream);
	while (prop_iter_next(&pi, flags & RAZOR_PROPERTY_TYPE_MASK, &p)) {
		if (!(trans->upstream.properties[p - pi.start] & TRANS_PROPERTY_SATISFIED) &&
		    p->flags == flags &&
		    strcmp(&pi.pool[p->name], name) == 0 &&
		    strcmp(&pi.pool[p->version], version) == 0)

			return 1;
	}

	return 0;
}

RAZOR_EXPORT struct razor_set *
razor_transaction_finish(struct razor_transaction *trans)
{
	struct razor_merger *merger;
	struct razor_package *u, *uend, *upkgs, *s, *send, *spkgs;
	char *upool, *spool;
	int cmp;

	s = trans->system.set->packages.data;
	spkgs = trans->system.set->packages.data;
	send = trans->system.set->packages.data +
		trans->system.set->packages.size;
	spool = trans->system.set->string_pool.data;

	u = trans->upstream.set->packages.data;
	upkgs = trans->upstream.set->packages.data;
	uend = trans->upstream.set->packages.data +
		trans->upstream.set->packages.size;
	upool = trans->upstream.set->string_pool.data;

	merger = razor_merger_create(trans->system.set, trans->upstream.set);
	while (s < send || u < uend) {
		if (s < send && u < uend)
			cmp = strcmp(&spool[s->name], &upool[u->name]);
		else if (s < send)
			cmp = -1;
		else
			cmp = 1;

		if (cmp < 0) {
			if (trans->system.packages[s - spkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, s);
			s++;
		} else if (cmp == 0) {
			if (trans->system.packages[s - spkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, s);
			if (trans->upstream.packages[u - upkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, u);

			s++;
			u++;
		} else {
			if (trans->upstream.packages[u - upkgs] & TRANS_PACKAGE_PRESENT)
				razor_merger_add_package(merger, u);
			u++;
		}
	}

	razor_transaction_destroy(trans);

	return razor_merger_finish(merger);
}

RAZOR_EXPORT void
razor_transaction_destroy(struct razor_transaction *trans)
{
	assert (trans != NULL);

	transaction_set_release(&trans->system);
	transaction_set_release(&trans->upstream);
	free(trans);
}
