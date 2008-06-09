CFLAGS = -Wall -Wstrict-prototypes -Wmissing-prototypes -g
LDLIBS = librazor.a -lexpat -lz -g -lrpm -lcurl

all : razor test-driver rpm-razor

librazor_objs = razor.o yum.o rpm.o types.o util.o
librazor.a : $(librazor_objs)
	ar cr $@ $(librazor_objs)

razor : main.o librazor.a

*.o : razor.h razor-internal.h
razor.o : types.h

test-driver : librazor.a test-driver.o

rpm-razor : librazor.a rpm-razor.o

test : test-driver
	./test-driver test.xml

reset : ./razor
	sudo rm -rf install
	./razor init

clean :
	rm -f *.o razor librazor.a
