#include <sodium.h>
#include <string.h>

#include "result.h"

//The seed is going to be the output of a BIP-39 function.
result MIST_ENCRYPT_SEED(
        unsigned char* output,
        unsigned long long output_length;
        unsigned char* MIST_NONCE_OUTPUT,
        unsigned char* MIST_SALT_OUTPUT,

        const unsigned char* MIST_SEED,
        const unsigned char* MIST_PASSPHRASE
) { //Don't forget to wipe your MIST_SEED variable!
    if (!check_libsodium) return libsodium_initialization_error;

    unsigned long long encryption_key_length = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
    unsigned char encryption_key[encryption_key_length];

    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    if (crypto_pwhash(
        encryption_key,
        encryption_key_length,
        strlen(MIST_PASSPHRASE),
        MIST_SALT_OUTPUT,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0)
        return out_of_memory;

    crypto_aead_xchacha20poly1305_ietf_encrypt(
            output,
            &output_length,
            MIST_SEED,
            MIST_SEED_LENGTH, //Defined at constants.h
            NULL,
            0,
            NULL,
            MIST_NONCE_OUTPUT,
            encryption_key
    );

    sodium_memzero(encryption_key, encryption_key_length);

    return success;
}

result MIST_DECRYPT_SEED(
    unsigned char* output,
    unsigned long long output_length,

    const unsigned char* MIST_NONCE,
    const unsigned char* MIST_SALT,
    const unsigned char* MIST_CIPHERTEXT,
    const long long ciphertext_length,
    const unsigned char* MIST_PASSPHRASE,
    const size_t passphrase_length
) { //Don't forget to wipe your MIST_PASSPHRASE variable!
    if (!check_libsodium) return libsodium_initialization_error;

    unsigned long long encryption_key_length = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
    unsigned char encryption_key[encryption_key_length];

    if (crypto_pwhash(
        encryption_key,
        encryption_key_length,
        strlen(MIST_PASSPHRASE),
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0)
        return out_of_memory;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        output,
        &output_length,
        NULL,
        MIST_CIPHERTEXT,
        ciphertext_length,
        NULL,
        0,
        MIST_NONCE,
        MIST_ENCRYPTION_KEY
    ) != 0)
        return seed_decryption_error;

    sodium_memzero(encryption_key, encryption_key_length);

    return success;
}
