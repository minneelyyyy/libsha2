PREFIX?=/usr/local

OBJS=src/sha256/sha256.o src/sha256/x86/avx2.o src/sha256/generic.o
TESTS=tests/basic tests/stream tests/sha256sum tests/miner tests/miner-mt

CFLAGS += -Iinclude -mavx -mavx2 -msse -msse2 -msse3 -msse4.1 -msse4.2

.PHONY: all install uninstall tests clean
.SUFFIXES: .c .o

all: libsha2.so libsha2.a
tests: $(TESTS)

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

libsha2.so: $(OBJS) src/streaming.c
	$(CC) $(LDFLAGS) -shared -o $@ $(OBJS)

libsha2.a: $(OBJS) src/streaming.c
	$(AR) $(ARFLAGS) $@ $(OBJS)

tests/basic: libsha2.a tests/basic.o
	$(CC) $(LDFLAGS) -o $@ tests/basic.o libsha2.a

tests/stream: libsha2.a tests/stream.o
	$(CC) $(LDFLAGS) -o $@ tests/stream.o libsha2.a

tests/sha256sum: libsha2.a tests/sha256sum.o
	$(CC) $(LDFLAGS) -o $@ tests/sha256sum.o libsha2.a

tests/miner: libsha2.a tests/miner.o
	$(CC) $(LDFLAGS) -o $@ tests/miner.o libsha2.a

tests/miner-mt: libsha2.a tests/miner-mt.o
	$(CC) $(LDFLAGS) -o $@ tests/miner-mt.o libsha2.a

install: libsha2.so libsha2.a
	install -m 755 libsha2.so $(PREFIX)/lib
	install -m 744 libsha2.a $(PREFIX)/lib
	cp -r include/sha2/ $(PREFIX)/include/sha2

clean:
	rm -f $(OBJS) $(TESTS) tests/*.o libsha2.so libsha2.a
