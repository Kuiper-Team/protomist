#ifndef types_h
#define types_h

#include "constants.h"

//BIP-39

typedef struct {
    unsigned char* key; //Bytes
    char* value; //String
} bip39_wordlist_pair;

typedef enum {
    en, //English
    ja, //Japanese
    ko, //Korean
    es, //Spanish
    zh_HANS, //Chinese (Simplified)
    zh_HANT, //Chinese (Traditional)
    fr, //French
    it, //Italian
    cs, //Czech
    pt, //Portuguese
    ru, //Russian
    tr //Turkish
} bip39_wordlist_language;

#endif
