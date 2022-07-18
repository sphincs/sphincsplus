PARAMS = sphincs-haraka-128f
THASH = robust

CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)


SOURCES = hash_haraka.c hash_harakax4.c thash_haraka_$(THASH).c thash_haraka_$(THASH)x4.c address.c randombytes.c merkle.c wots.c utils.c utilsx4.c fors.c sign.c haraka.c
HEADERS = params.h hash.h hashx4.h thash.h thashx4.h address.h randombytes.h merkle.c wots.h utils.h utilsx4.h fors.h api.h haraka.h harakax4.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/fors \
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
