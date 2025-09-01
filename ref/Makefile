PARAMS = sphincs-sha2-128f
THASH = simple

CC = gcc
CFLAGS=-Wall -Wextra -Wpedantic -O3 -std=c99 -Wconversion -Wmissing-prototypes -DPARAMS=$(PARAMS) $(EXTRA_CFLAGS)
ifeq ($(THASH),robust)
	CFLAGS += -DSPX_ROBUST=1
endif
LDLIBS = -lcrypto

SOURCES =          address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c
HEADERS = params.h address.h randombytes.h merkle.h wots.h wotsx1.h utils.h utilsx1.h fors.h api.h  hash.h thash.h

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += fips202.c hash_shake.c thash_shake_$(THASH).c
	HEADERS += fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	SOURCES += haraka.c hash_haraka.c thash_haraka_$(THASH).c
	HEADERS += haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	SOURCES += sha2.c hash_sha2.c thash_sha2_$(THASH).c
	HEADERS += sha2.h
endif

DET_SOURCES = $(SOURCES:randombytes.%=rng.%)
DET_HEADERS = $(HEADERS:randombytes.%=rng.%)

TESTS =         test/fors \
		test/spx \

BENCHMARK = test/benchmark

.PHONY: clean test benchmark

test_sphincsplus: test_sphincsplus.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

default: PQCgenKAT_sign

all: PQCgenKAT_sign tests benchmarks

tests: $(TESTS)

test: $(TESTS:=.exec)

benchmarks: $(BENCHMARK)

benchmark: $(BENCHMARK:=.exec)

PQCgenKAT_sign: PQCgenKAT_sign.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< -lcrypto

test/benchmark: test/benchmark.c test/cycles.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ test/cycles.c $(DET_SOURCES) $< $(LDLIBS)

test/%: test/%.c $(DET_SOURCES) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(DET_SOURCES) $< $(LDLIBS)

test/haraka: test/haraka.c $(filter-out haraka.c,$(DET_SOURCES)) $(DET_HEADERS)
	$(CC) $(CFLAGS) -o $@ $(filter-out haraka.c,$(DET_SOURCES)) $< $(LDLIBS)

test/%.exec: test/%
	@$<

clean:
	-$(RM) $(TESTS)
	-$(RM) $(BENCHMARK)
	-$(RM) PQCgenKAT_sign
	-$(RM) PQCsignKAT_*.rsp
	-$(RM) PQCsignKAT_*.req
