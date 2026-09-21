#ifndef subkey_h
#define subkey_h

#include <stddef.h>
#include <stdint.h>

#include "key.h"
#include "result.h"

typedef struct {
    mist_key_signing* key;
    uint32_t identifier;
} mist_subkey_signing;

typedef struct {
    mist_key_encryption* key;
    uint32_t identifier;
} mist_subkey_encryption;

typedef struct {
    mist_key_symmetric_encryption* key;
    uint32_t identifier;
} mist_subkey_symmetric_encryption;

typedef struct {
    mist_key_key_encapsulation* key;
    uint32_t identifier;
} mist_subkey_key_encapsulation;

result mist_subkey_signing_encryption(
    mist_subkey_signing* output,

    const uint32_t identifier
);

result mist_subkey_encryption_generate(
    mist_subkey_encryption* output,

    const uint32_t identifier
);

result mist_subkey_symmetric_encryption_generate(
    mist_subkey_symmetric_encryption* output,

    const uint32_t identifier
);

result mist_subkey_key_encapsulation_generate(
    mist_subkey_key_encapsulation* output,

    const uint32_t identifier
);

#endif
