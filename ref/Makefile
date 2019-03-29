CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -std=c99

HASH = shake256
THASH = robust

SOURCES =          address.c randombytes.c wots.c utils.c fors.c sign.c hash_$(HASH).c thash_$(HASH)_$(THASH).c
HEADERS = params.h address.h randombytes.h wots.h utils.h fors.h api.h  hash.h thash.h

ifeq ($(HASH),shake256)
	SOURCES += fips202.c
	HEADERS += fips202.h
endif
ifeq ($(HASH),haraka)
	SOURCES += haraka.c
	HEADERS += haraka.h
endif
ifeq ($(HASH),sha256)
	SOURCES += sha256.c
	HEADERS += sha256.h
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

test/haraka: test/haraka.c $(filter-out haraka.c,$(SOURCES)) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(filter-out haraka.c,$(SOURCES)) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
