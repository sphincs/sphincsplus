CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3
HASH_C = hash_shake256.c

SOURCES =          $(HASH_C) hash_address.c randombytes.c wots.c utils.c fors.c sign.c
HEADERS = params.h hash.h    hash_address.h randombytes.h wots.h utils.h fors.h api.h

ifeq ($(HASH_C),hash_shake256.c)
	SOURCES += fips202.c
	HEADERS += fips202.h
endif
ifeq ($(HASH_C),hash_haraka.c)
	SOURCES += haraka.c
	HEADERS += haraka.h
endif
ifeq ($(HASH_C),hash_sha256.c)
	LDLIBS += -lcrypto
endif

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/wots \
		test/fors \
		test/spx \

BENCHMARK = test/benchmark

.PHONY: clean test benchmark

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/%: test/%.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
