# The name of the module.
DOC_MODULE=razor

# The top-level SGML file.
DOC_MAIN_SGML_FILE=razor-docs.xml

# Extra options to supply to gtkdoc-scan
IGNORE_HFILES = config.h razor-internal.h

# The directory containing the source code. Relative to $(srcdir)
DOC_SOURCE_DIR=$(top_srcdir)/librazor

# Used for dependencies
HFILE_GLOB=$(top_srcdir)/librazor/*.h
CFILE_GLOB=$(top_srcdir)/librazor/*.c

# Extra options to supply to gtkdoc-mkdb
MKDB_OPTIONS=--sgml-mode --output-format=xml

# Extra options to supply to gtkdoc-mktmpl
MKTMPL_OPTIONS=

include $(top_srcdir)/gtk-doc.make

# Version information for marking the documentation
EXTRA_DIST += version.xml.in

docsdir = $(datadir)/doc/razor
dist_docs_DATA = 		\
	DEPSOLVE.txt 		\
	REPO.txt

