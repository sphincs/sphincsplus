# This Makefile can be used with GNU Make or BSD Make

LIB=libsphincs_clean.a

HEADERS = params.h address.h wots.h utils.h utilsx8.h sha256avx.h sha256x8.h fors.h api.h hash.h hashx8.h hash_state.h thash.h thashx8.h HASHHEADERS
OBJECTS =          address.o wots.o utils.o utilsx8.o sha256avx.o sha256x8.o fors.o hash_sha256x8.o sign.oHASHOBJECTS

CFLAGS=-mavx2 -O3 -Wall -Wconversion -Wextra -Wpedantic -Wvla -Werror -Wmissing-prototypes -Wredundant-decls -std=c99 -I../../../common $(EXTRAFLAGS)

all: $(LIB)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
