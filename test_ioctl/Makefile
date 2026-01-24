# Makefile for F2FS snapshot test tools

CC = gcc
CFLAGS = -Wall -O2

TARGETS = test test_delete

all: $(TARGETS)

test: test.c
	$(CC) $(CFLAGS) -o test test.c

test_delete: test_delete.c
	$(CC) $(CFLAGS) -o test_delete test_delete.c

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
