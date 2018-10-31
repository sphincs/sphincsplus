CC = /usr/bin/gcc
CFLAGS = -g -Wall -Wextra -Wpedantic -O3 -march=native -fomit-frame-pointer -flto
HASH_C = hash_sha256.c
LDLIBS += -lcrypto

SOURCES =          $(HASH_C) hash_sha256x8.c sha256avx.c address.c randombytes.c wots.c utils.c utilsx8.c fors.c sign.c
HEADERS = params.h hash.h    hashx8.h        sha256avx.h address.h randombytes.h wots.h utils.h utilsx8.h fors.h api.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/wots \
		test/fors \
		test/spx \
		test/thashx8 \

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
