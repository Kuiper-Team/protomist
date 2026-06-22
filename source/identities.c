#include <sodium.h>
#include <string.h>

#include "result.h"

//check_libsodium() should be included from helpers.h.
//MIST_SEED_LENGTH should be included from constants.h.

result MIST_ENCRYPT_SEED(
        unsigned char* output,
        unsigned char* nonce_output,
        unsigned long long ciphertext_length;

        const unsigned char* MIST_SEED,
        const unsigned char* MIST_PASSPHRASE,
        const size_t passphrase_length
) {
    if (!libsodium_check)
        return libsodium_initialization_error;

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char encryption_key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(salt, sizeof(salt));
    if (crypto_pwhash(
        encryption_key,
        sizeof(encryption_key),
        strlen(MIST_PASSPHRASE),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0)
        return out_of_memory;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            output,
            &ciphertext_length,
            MIST_SEED,
            MIST_SEED_LENGTH,
            NULL,
            0,
            NULL,
            nonce,
            encryption_key
    );
}
