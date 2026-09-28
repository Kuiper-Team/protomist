C := gcc

CFLAGS := -std=c11 -g

LDFLAGS := -lsodium -lxeddsa -g
WARNINGFLAGS := -Wall -Wextra

CINCLUDEFLAGS := source/serialization/generated

ASN1CGENERATEDC := $(wildcard source/serialization/generated/*.c)
ASN1CGENERATEDOBJECTS := $(ASN1CGENERATEDC:.c=.o)

COBJECTS := \
	$(ASN1CGENERATEDOBJECTS) \
	source/bech32/ref.o \
	source/bech32/wrapper.o \
	source/helpers.o \
	source/identity.o \
	source/initialize.o \
	source/key.o \
	source/pqxdh.o \
	source/subkey.o \
	source/serialization/decoder.o \
	source/serialization/encoder.o \
	examples/identity_creation.o

CPPOBJECTS := \
	source/bech32/bech32.o \
	source/bech32/wrapper.o

identity_creation.o: $(COBJECTS) $(CPPOBJECTS)
	$(C) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(C) $(CFLAGS) -c $< -o $@ -I $(CINCLUDEFLAGS) $(WARNINGFLAGS)

clean:
	rm -f $(COBJECTS) $(CPPOBJECTS) identity_creation.o
