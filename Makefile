C := gcc
CPP := g++

CFLAGS := -std=c11 \
	-DBLAKE3_NO_AVX2 \
	-DBLAKE3_NO_AVX512 \
	-DBLAKE3_NO_SSE2 \
	-DBLAKE3_NO_SSE41
CPPFLAGS := -std=c++17

LDFLAGS := -lsodium

CPPINCLUDEFLAGS := source/bech32

COBJECTS := \
	source/bech32/convert_bits.o \
	source/blake3/blake3.o \
	source/blake3/blake3_dispatch.o \
	source/blake3/blake3_portable.o \
	source/identity.o \
	source/wordlists/apply.o \
	source/wordlists/languages.o \
	examples/identity.o

CPPOBJECTS := \
	source/bech32/bech32.o \
	source/bech32/wrapper.o

identity_creation.o: $(COBJECTS) $(CPPOBJECTS)
	$(CPP) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(C) $(CFLAGS) -c $< -o $@

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@ -I $(CPPINCLUDEFLAGS) -Wall -Wextra

clean:
	rm -f $(COBJECTS) $(CPPOBJECTS) identity_creation.o
