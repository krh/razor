CFLAGS = -Wall -g
LDLIBS = -lexpat -lz -g -lrpm -lcurl

all : razor test-driver

razor : razor.o yum.o main.o rpm.o types.o util.o

*.o : razor.h razor-internal.h
razor.o : types.h

test-driver : razor.o types.o util.o test-driver.o

test : test-driver
	./test-driver test.xml

clean :
	rm -f *.o razor
