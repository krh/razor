CFLAGS = -Wall -g
LDLIBS = -lexpat -g

razor : razor.o sha1.o

clean :
	rm -f *.o razor
