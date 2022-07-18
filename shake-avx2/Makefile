PARAMS = sphincs-shake-128f
THASH = robust

CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -Wmissing-prototypes -O3 -std=c99 -march=native -fomit-frame-pointer -flto -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)

SOURCES =          hash_shake.c hash_shakex4.c thash_shake_$(THASH).c thash_shake_$(THASH)x4.c address.c randombytes.c merkle.c wots.c utils.c utilsx4.c fors.c sign.c fips202.c fips202x4.c keccak4x/KeccakP-1600-times4-SIMD256.o
HEADERS = params.h hash.h          hashx4.h          thash.h                 thashx4.h                 address.h randombytes.h merkle.h wots.h utils.h utilsx4.h fors.h api.h fips202.h fips202x4.h

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS = test/fors \
		test/spx \
		test/thashx4 \

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

keccak4x/KeccakP-1600-times4-SIMD256.o: keccak4x/align.h \
										keccak4x/brg_endian.h \
										keccak4x/KeccakP-1600-times4-SIMD256.c \
										keccak4x/KeccakP-1600-times4-SnP.h \
										keccak4x/KeccakP-1600-unrolling.macros \
										keccak4x/SIMD256-config.h
	$(CC) $(CFLAGS) -c keccak4x/KeccakP-1600-times4-SIMD256.c -o $@

clean:
	-$(RM) keccak4x/KeccakP-1600-times4-SIMD256.o
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
