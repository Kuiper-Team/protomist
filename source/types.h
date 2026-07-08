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
    cs, //Czech
    es, //Spanish
    fr, //French
    it, //Italian
    ja, //Japanese
    ko, //Korean
    pt, //Portuguese
    ru, //Russian
    tr, //Turkish
    zh_HANS, //Chinese (Simplified)
    zh_HANT //Chinese (Traditional)
} bip39_wordlist_language;

#endif
