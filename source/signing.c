#include "signing.h"

#include <sodium.h>
#include <stddef.h>

#include "constants.h"
#include "identity.h"
#include "result.h"

result mist_signing_sign(
    unsigned char** output,

    const struct mist_identity identity,
    const unsigned char* input,
    const size_t input_size
) {
    unsigned char signature[crypto_sign_BYTES + payload_size];
    size_t signature_size;
    crypto_sign(
        *output,
        (size_t*) &signature_size,
        payload,
        payload_size,
        identity.secret_key,
    );

    return success;
}

result mist_signing_verify(
    const unsigned char* public_key,
    const unsigned char* signature,
    const size_t signature_size
) {
    if (crypto_sign_open(
        NULL,
        NULL,
        signature,
        signature_size,
        public_key
    ) != 0)
        return incorrect_signature;
    else
        return success;
}
