CFLAGS = -Wall -g -O2
LDLIBS = -lexpat -lz -g -lrpm -lcurl

all : razor test-driver

razor : razor.o import.o main.o rpm.o

test-driver : razor.o test-driver.o

test : test-driver
	./test-driver sets.xml test.xml

clean :
	rm -f *.o razor
