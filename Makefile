CFLAGS = -Wall -g -O2
LDLIBS = -lexpat -lz -g -lrpm -lcurl

razor : razor.o import.o sha1.o main.o

clean :
	rm -f *.o razor
