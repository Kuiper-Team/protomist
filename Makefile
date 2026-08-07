C := gcc
CPP := g++

CFLAGS := -std=c11
CPPFLAGS := -std=c++17

LDFLAGS := -lsodium
WARNINGFLAGS := -Wall -Wextra -Wno-unused-parameter

CPPINCLUDEFLAGS := source/bech32

COBJECTS := \
	source/bech32/convert_bits.o \
	source/contacts.o \
	source/helpers.o \
	source/identity.o \
	source/pqxdh.o \
	source/wordlists/apply.o \
	source/wordlists/languages.o \
	examples/identity_creation.o

CPPOBJECTS := \
	source/bech32/bech32.o \
	source/bech32/wrapper.o

identity_creation.o: $(COBJECTS) $(CPPOBJECTS)
	$(CPP) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(C) $(CFLAGS) -c $< -o $@ $(WARNINGFLAGS)

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@ -I $(CPPINCLUDEFLAGS) $(WARNINGFLAGS)

clean:
	rm -f $(COBJECTS) $(CPPOBJECTS) identity_creation.o
