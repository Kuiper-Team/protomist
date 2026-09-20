#include "identity.h"

#include <sodium.h>
#include <string.h>

#include "constants.h"
#include "result.h"

result mist_identity_subkey_generate_signing(
    mist_identity_subkey_signing* output
) {
    crypto_sign_keypair(output->public_key, output->secret_key);

    return success;
}

result mist_identity_subkey_generate_encryption(
    mist_identity_subkey_encryption* output
) {
    crypto_box_keypair(output->public_key, output->secret_key);

    return success;
}

result mist_identity_subkey_generate_symmetric_encryption(
    mist_identity_subkey_symmetric_encryption* output
) {
    crypto_aead_xchacha20poly1305_ietf_keygen(output->key);
    randombytes_buf(output->nonce, sizeof(output->nonce));

    return success;
}

result mist_identity_subkey_generate_key_encapsulation(
    mist_identity_subkey_key_encapsulation* output
) {
    crypto_kem_mlkem768_keypair(output->public_key, output->secret_key);

    return success;
}

result mist_identity_generate(
    mist_identity* output
) {
    mist_identity_subkey_generate_signing(output);

    return success;
}
