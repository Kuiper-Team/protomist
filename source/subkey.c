#include "subkey.h"

#include <stddef.h>
#include <stdint.h>

#include "key.h"
#include "result.h"

result mist_subkey_signing_encryption(
    mist_subkey_signing* output,

    const uint32_t identifier
) {
    *output = {0};
    mist_key_signing_generate(output->key);
    output.identifier = identifier;

    return success;
}

result mist_subkey_key_agreement_generate(
    mist_subkey_key_agreement* output,

    const uint32_t identifier
) {
    *output = {0};
    mist_key_key_agreement_generate(output->key);
    output.identifier = identifier;

    return success;
}

result mist_subkey_encryption_generate(
    mist_subkey_encryption* output,

    const uint32_t identifier
) {
    *output = {0};
    mist_key_encryption_generate(output->key);
    output.identifier = identifier;

    return success;
}

result mist_subkey_key_encapsulation_generate(
    mist_subkey_key_encapsulation* output,

    const uint32_t identifier
) {
    *output = {0};
    mist_key_key_encapsulation_generate(output->key);
    output.identifier = identifier;

    return success;
}
