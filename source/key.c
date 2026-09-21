#include "key.h"

#include <sodium.h>
#include <stddef.h>

#include "identity.h"
#include "result.h"

result mist_key_signing_generate(
    mist_key_signing* output
) {
    crypto_sign_keypair(output->public_key, output->secret_key);

    return success;
}

result mist_key_agreement_generate(
    mist_key_agreement* output
) {
    crypto_box_keypair(output->public_key, output->secret_key);

    return success;
}

result mist_key_encryption_generate(
    mist_key_encryption* output
) {
    crypto_aead_xchacha20poly1305_ietf_keygen(output->key);
    randombytes_buf(output->nonce, sizeof(output->nonce));

    return success;
}

result mist_key_key_encapsulation_generate(
    mist_key_key_encapsulation* output
) {
    crypto_kem_mlkem768_keypair(output->public_key, output->secret_key);

    return success;
}

result mist_key_signing_sign(
    unsigned char* output,

    const mist_key_signing signer,
    const unsigned char* input,
    const size_t input_size
) {
    unsigned char signature[crypto_sign_BYTES + input_size];
    size_t signature_size = 0;
    crypto_sign(
        output,
        (size_t*) &signature_size,
        payload,
        payload_size,
        signer.secret_key,
    );

    return success;
}

result mist_key_signing_verify(
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
