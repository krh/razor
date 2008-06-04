CFLAGS = -Wall -Wstrict-prototypes -Wmissing-prototypes -g
LDLIBS = -lexpat -lz -g -lrpm -lcurl

all : razor test-driver rpm-razor

razor : razor.o yum.o main.o rpm.o types.o util.o

*.o : razor.h razor-internal.h
razor.o : types.h

test-driver : razor.o types.o util.o test-driver.o

rpm-razor : rpm-razor.o razor.o types.o util.o rpm.o

test : test-driver
	./test-driver test.xml

reset : ./razor
	sudo rm -rf install
	./razor init

clean :
	rm -f *.o razor
