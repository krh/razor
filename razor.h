#ifndef _RAZOR_H_
#define _RAZOR_H_

struct razor_importer;

struct razor_importer *razor_importer_new(void);
void razor_importer_begin_package(struct razor_importer *importer,
				const char *name, const char *version);
void razor_importer_add_requires(struct razor_importer *importer,
				 const char *name, const char *version);
void razor_importer_add_provides(struct razor_importer *importer,
				 const char *name, const char *version);
void razor_importer_finish_package(struct razor_importer *importer);
struct razor_set *razor_importer_finish(struct razor_importer *importer);

struct razor_set *razor_import_rzr_files(int count, const char **files);
struct razor_set *razor_set_create_from_yum_filelist(int fd);
struct razor_set *razor_set_create_from_rpmdb(void);

#endif /* _RAZOR_H_ */
