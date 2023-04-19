PARAMS = sphincs-shake-128f
THASH = robust

CFLAGS = -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -fomit-frame-pointer -flto -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)

SOURCES =          hash_shake.c hash_shakex2.c thash_shake_$(THASH)x2.c address.c randombytes.c merkle.c wots.c utils.c utilsx2.c fors.c sign.c fips202.c fips202x2.c f1600x2_const.c f1600x2.s
HEADERS = params.h hash.h          hashx2.h                          thashx2.h                 address.h randombytes.h merkle.h wots.h utils.h utilsx2.h fors.h api.h fips202.h fips202x2.h f1600x2.h thash.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/fors \
		test/spx \
		test/thashx2 \

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

test/benchmark: test/benchmark.c test/cycles.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(SOURCES) $< $(LDLIBS)

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
