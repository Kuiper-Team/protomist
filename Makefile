C := gcc
CPP := g++

CFLAGS := -std=c11 -g
CPPFLAGS := -std=c++17 -g

LDFLAGS := -lsodium -lxeddsa -g
WARNINGFLAGS := -Wall -Wextra -Wno-missing-braces

CINCLUDEFLAGS := source/serialization/generated
CPPINCLUDEFLAGS := source/bech32

ASN1CGENERATEDC := $(wildcard source/serialization/generated/*.c)
ASN1CGENERATEDOBJECTS := $(ASN1CGENERATEDC:.c=.o)

COBJECTS := \
	source/bech32/convert_bits.o \
	source/contacts.o \
	source/helpers.o \
	source/identity.o \
	source/initialize.o \
	source/pqxdh.o \
	source/serialization/decoder.o \
	source/serialization/encoder.o \
	$(ASN1CGENERATEDOBJECTS) \
	source/wordlists/apply.o \
	source/wordlists/languages.o \
	examples/identity_creation.o

CPPOBJECTS := \
	source/bech32/bech32.o \
	source/bech32/wrapper.o

identity_creation.o: $(COBJECTS) $(CPPOBJECTS)
	$(CPP) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(C) $(CFLAGS) -c $< -o $@ -I $(CINCLUDEFLAGS) $(WARNINGFLAGS)

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@ -I $(CPPINCLUDEFLAGS) $(WARNINGFLAGS)

clean:
	rm -f $(COBJECTS) $(CPPOBJECTS) identity_creation.o
