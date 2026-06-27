#ifndef types_h
#define types_h

#include "constants.h"

//Work in progress

typedef struct {
    unsigned char bytes[MIST_SEED_SIZE];
} seed;

typedef enum {
    english,
    japanese,
    korean,
    spanish,
    chinese_simplified,
    chinese_traditional,
    french,
    italian,
    czech,
    portuguese,
    russian,
    turkish
} bip39_wordlist_language;

#endif
