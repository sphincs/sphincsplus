CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer

ROOT := ..

# SPHINCS+ parameters - adjust as needed
PARAMS ?= sphincs-sha2-128f
THASH ?= simple

# OS-specific adjustments for randombytes
ifeq ($(OS),Windows_NT)
    RANDOMBYTES_SRC = $(ROOT)/randombytes_win.c
    LDLIBS += -lbcrypt
else
    RANDOMBYTES_SRC = $(ROOT)/randombytes.c
endif

SOURCES = $(ROOT)/address.c $(RANDOMBYTES_SRC) $(ROOT)/merkle.c $(ROOT)/wots.c $(ROOT)/wotsx1.c $(ROOT)/utils.c $(ROOT)/utilsx1.c $(ROOT)/fors.c $(ROOT)/sign.c
HEADERS = $(ROOT)/params.h $(ROOT)/address.h $(ROOT)/randombytes.h $(ROOT)/merkle.h $(ROOT)/wots.h $(ROOT)/wotsx1.h $(ROOT)/utils.h $(ROOT)/utilsx1.h $(ROOT)/fors.h $(ROOT)/api.h $(ROOT)/hash.h $(ROOT)/thash.h

ifneq (,$(findstring shake,$(PARAMS)))
	SOURCES += $(ROOT)/fips202.c $(ROOT)/hash_shake.c $(ROOT)/thash_shake_$(THASH).c
	HEADERS += $(ROOT)/fips202.h
endif
ifneq (,$(findstring haraka,$(PARAMS)))
	SOURCES += $(ROOT)/haraka.c $(ROOT)/hash_haraka.c $(ROOT)/thash_haraka_$(THASH).c
	HEADERS += $(ROOT)/haraka.h
endif
ifneq (,$(findstring sha2,$(PARAMS)))
	SOURCES += $(ROOT)/sha2.c $(ROOT)/hash_sha2.c $(ROOT)/thash_sha2_$(THASH).c
	HEADERS += $(ROOT)/sha2.h
endif

.PHONY: all run-server run-client stress keygen clean

TARGET_IP ?= 192.168.4.85
CONCURRENT_SESSIONS ?= 10
BATCHES ?= 0
BATCH_DELAY_SEC ?= 0

CLIENT_BIN := test_sphincsplus_client
SERVER_BIN := test_sphincsplus_server
STRESS_BIN := test_sphincsplus_stress
KEYGEN_BIN := test_sphincsplus_keygen
TEST_BIN := test_sphincsplus
SPEED_BIN := test_speed
VECTORS_BIN := test_vectors

all: \
  test_sphincsplus_client \
  test_sphincsplus_server \
  test_sphincsplus_stress \
  test_sphincsplus_keygen \
  test_sphincsplus \
  test_speed \
  test_vectors

test_sphincsplus_client: test_sphincsplus_client.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMS=$(PARAMS) -DSPX_ROBUST=0 \
	  -o $@ $< $(SOURCES) $(LDLIBS)

test_sphincsplus_server: test_sphincsplus_server.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMS=$(PARAMS) -DSPX_ROBUST=0 \
	  -o $@ $< $(SOURCES) $(LDLIBS)

test_sphincsplus_stress: test_sphincsplus_stress.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMS=$(PARAMS) -DSPX_ROBUST=0 \
	  -o $@ $< $(SOURCES) $(LDLIBS)

test_sphincsplus_keygen: test_sphincsplus_keygen.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMS=$(PARAMS) -DSPX_ROBUST=0 \
	  -o $@ $< $(SOURCES) $(LDLIBS)

test_sphincsplus: test_sphincsplus.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMS=$(PARAMS) -DSPX_ROBUST=0 \
	  -o $@ $< $(SOURCES) $(LDLIBS)

test_speed: test_speed.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMS=$(PARAMS) -DSPX_ROBUST=0 \
	  -o $@ $< $(SOURCES) $(LDLIBS)

test_vectors: test_vectors.c $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -DPARAMS=$(PARAMS) -DSPX_ROBUST=0 \
	  -o $@ $< $(SOURCES) $(LDLIBS)

run-server: $(SERVER_BIN)
	@echo "[RUN] Server on port 5000"
	@./$(SERVER_BIN)

run-client: $(CLIENT_BIN)
	@echo "[RUN] Client -> $(TARGET_IP)"
	@./$(CLIENT_BIN) $(TARGET_IP)

stress: $(STRESS_BIN)
	@echo "[STRESS] TARGET_IP=$(TARGET_IP) CONCURRENT=$(CONCURRENT_SESSIONS)"
	@TARGET_IP=$(TARGET_IP) CONCURRENT_SESSIONS=$(CONCURRENT_SESSIONS) \
	  BATCHES=$(BATCHES) BATCH_DELAY_SEC=$(BATCH_DELAY_SEC) \
	  ./$(STRESS_BIN)

keygen: $(KEYGEN_BIN)
	@echo "[KEYGEN]"
	@./$(KEYGEN_BIN)

clean:
	rm -f test_sphincsplus_client
	rm -f test_sphincsplus_server
	rm -f test_sphincsplus_stress
	rm -f test_sphincsplus_keygen
	rm -f test_sphincsplus
	rm -f test_speed
	rm -f test_vectors