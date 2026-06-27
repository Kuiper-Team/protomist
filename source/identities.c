#include "identities.h"

#include <sodium.h>
#include <string.h>

#include "constants.h"
#include "helpers.h"
#include "result.h"
#include "types.h"

#include "wordlists/apply.h"

result MIST_SEED_GENERATE_MNEMONIC_SENTENCE(
    unsigned char* output,

    const bip39_wordlist_language language
) {
    unsigned char bip39_entropy[MIST_SEED_ENTROPY_SIZE];
    randombytes_buf(bip39_entropy, sizeof(bip39_entropy));

    unsigned char checksum_input[MIST_SEED_CHECKSUM_INPUT_SIZE];
    memcpy(checksum_input, bip39_entropy, MIST_SEED_CHECKSUM_INPUT_SIZE);

    unsigned char checksum[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(
        checksum,
        checksum_input,
        sizeof(checksum_input)

    apply_wordlist( //Not yet implemented.
        output,
        bip39_entropy,
        language
    )

    sodium_memzero(bip39_entropy);
    sodium_memzero(checksum_input);
    sodium_memzero(checksum);

    return success;
}

result MIST_GENERATE_SEED(
    unsigned char* output,

    const unsigned char* MIST_SEED_MNEMONIC_SENTENCE
) {
    custom_pbkdf2_hmac_sha512( //Defined at custom_pbkdf2_hmac_sha512.h
        output,
        MIST_SEED_MNEMONIC_SENTENCE,
        seed_generation_salt,
        MIST_SEED_ITERATIONS,
        MIST_SEED_SIZE
    );

    return success;
}

result MIST_ENCRYPT_SEED(
    unsigned char* output,
    unsigned long long output_length,
    unsigned char* MIST_NONCE_OUTPUT,
    unsigned char* MIST_SALT_OUTPUT,

    const unsigned char* MIST_SEED,
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
) { //Don't forget to wipe your MIST_SEED and MIST_PASSPHRASE variables!
    if (!check_libsodium()) return libsodium_initialization_error;

    unsigned long long encryption_key_length = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
    unsigned char encryption_key[encryption_key_length];

    randombytes_buf(MIST_NONCE_OUTPUT, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(MIST_SALT_OUTPUT, crypto_pwhash_SALTBYTES);
    if (crypto_pwhash(
        encryption_key,
        encryption_key_length,
        MIST_PASSPHRASE,
        passphrase_length,
        MIST_SALT_OUTPUT,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0) {
        sodium_memzero(encryption_key, encryption_key_length);

        return seed_hashing_error;
    }

    if(crypto_aead_xchacha20poly1305_ietf_encrypt(
        output,
        &output_length,
        MIST_SEED,
        MIST_SEED_SIZE, //Defined in constants.h
        NULL,
        0,
        NULL,
        MIST_NONCE_OUTPUT,
        encryption_key
    ) != 0) {
        sodium_memzero(encryption_key, encryption_key_length);

        return seed_encryption_error;
    }

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
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
) { //Don't forget to wipe your MIST_PASSPHRASE variable!
    if (!check_libsodium()) return libsodium_initialization_error;

    unsigned long long encryption_key_length = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
    unsigned char encryption_key[encryption_key_length];

    if (crypto_pwhash(
        encryption_key,
        encryption_key_length,
        MIST_PASSPHRASE,
        passphrase_length,
        MIST_SALT,
        crypto_pwhash_OPSLIMIT_INTERACTIVE, //MIST_ARGON2ID_OPERATIONS_LIMIT
        crypto_pwhash_MEMLIMIT_INTERACTIVE, //MIST_ARGON2ID_MEMORY_LIMIT
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0) {
        sodium_memzero(encryption_key, encryption_key_length);

        return seed_hashing_error;
    }

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
    ) != 0) {
        sodium_memzero(encryption_key, encryption_key_length);

        return seed_decryption_error;
    }

    sodium_memzero(encryption_key, encryption_key_length);

    return success;
}
