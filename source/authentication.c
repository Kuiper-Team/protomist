#include "authentication.h"

#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>

#include "bech32/wrapper.h"
#include "constants.h"
#include "result.h"

//https://libsodium.gitbook.io/doc/key_derivation
result MIST_GENERATE_AUTHENTICATION_SUBKEY(
    unsigned char* output,

    const unsigned char* PARENT_KEY
) { //WIP. A generic MIST_GENERATE_SUBKEY() will be added to identity.h.
    return success;
}

result MIST_SIGN(
    char* output, //Bech32

    const char* MIST_SECRET_KEY, //Bech32
    const unsigned char* MIST_PAYLOAD,
    const size_t payload_size
) {
    unsigned char* ed25519_sk;
    MIST_BECH32M_DECODE(
        &ed25519_sk,
        MIST_SECRET_KEY
    );

    unsigned char signed_binary[crypto_sign_BYTES + payload_size];
    size_t signed_size;
    crypto_sign(
        output_binary,
        &signed_size,
        MIST_PAYLOAD,
        payload_size,
        ed25519_sk
    );
    sodium_memzero(crypto_sign_ed25519_SECRETKEYBYTES);

    const result r = MIST_BECH32M_ENCODE(
        &output,
        MIST_BECH32M_HRP_SIGNATURE,
        signed_binary,
        signed_size
    );

    return r;
}

result MIST_VERIFY_SIGNATURE(
    const char* MIST_ADDRESS, //Bech32
    const unsigned char* MIST_PAYLOAD,
    const size_t payload_size,
    const char* MIST_ED25519_SIGNATURE //Bech32
) {
    unsigned char* ed25519_pk;
    MIST_BECH32M_DECODE(
        &ed25519_pk,
        MIST_ADDRESS
    );

    unsigned char* signature;
    MIST_BECH32M_DECODE(
        &signature,
        MIST_ED25519_SIGNATURE
    );

    if (crypto_sign_open(
        MIST_PAYLOAD,
        &payload_size,
        MIST_ED25519_SIGNATURE,
        signature_size,
        MIST_ED25519_PUBLIC_KEY
    ) != 0)
        return incorrect_signature;
    else
        return success;
}
