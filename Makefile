CFLAGS = -Wall -g -O2
LDLIBS = -lexpat -lz -g -lrpm

razor : razor.o import.o sha1.o main.o

import : razor primary.xml.gz
	zcat primary.xml.gz | ./razor import-yum

primary.xml.gz :
	wget http://download.fedora.redhat.com/pub/fedora/linux/development/i386/os/repodata/primary.xml.gz

clean :
	rm -f *.o razor
