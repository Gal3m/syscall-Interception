CC=gcc
CFLAGS=-g -Wall -Werror

all: url2file

url2file: url2file.o
	$(CC) $(CFLAGS) -o url2file url2file.o

url2file.o: url2file.c
	$(CC) $(CFLAGS) -c url2file.c
	
clean:
	rm -f *.o url2file
