CFLAGS = -Wall -g -O2
LDLIBS = -lexpat -g

razor : razor.o sha1.o

clean :
	rm -f *.o razor
