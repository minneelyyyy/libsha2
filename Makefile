
OBJS=src/sha256.o
TESTS=tests/basic

.PHONY: all tests clean
.SUFFIXES: .c .o

all: libsha2.so libsha2.a
tests: $(TESTS)

CFLAGS += -Iinclude

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

libsha2.so: $(OBJS)
	$(CC) $(LDFLAGS) -shared -o $@ $(OBJS)

libsha2.a: $(OBJS)
	$(AR) $(ARFLAGS) $@ $(OBJS)

tests/basic: libsha2.a tests/basic.o
	$(CC) $(LDFLAGS) -o $@ tests/basic.o libsha2.a

clean:
	rm -f $(OBJS) tests/basic tests/*.o libsha2.so libsha2.a
