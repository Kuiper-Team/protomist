#include "identity.h"

#include <assert.h>
#include <sodium.h>
#include <stddef.h>
#include <string.h>

#include "bech32/wrapper.h"
#include "constants.h"
#include "helpers.h"
#include "result.h"
#include "wordlists/apply.h"

result MIST_GENERATE_MNEMONIC_SENTENCE(
    char** output,

    const char* const* list_pointer
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
    );

    unsigned char* mnemonic_input;
    concatenate_bytes(
        &mnemonic_input,
        bip39_entropy,
        sizeof(bip39_entropy),
        checksum,
        sizeof(checksum)
    );

    apply_wordlist(
        &output,
        mnemonic_input,
        list_pointer
    );

    sodium_memzero(bip39_entropy, MIST_SEED_ENTROPY_SIZE);
    sodium_memzero(checksum_input, MIST_SEED_CHECKSUM_INPUT_SIZE);
    sodium_memzero(checksum, crypto_hash_sha256_BYTES);

    return success;
}

result MIST_JOIN_MNEMONIC_SENTENCE(
    char** output, //Don't forget to free().
    size_t output_length,

    char** MIST_MNEMONIC_SENTENCE
) {
    output_length = 0;

    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        const char* word = MIST_MNEMONIC_SENTENCE[index];
        output_length += strlen(word);
    }
    const size_t space_count = MIST_SEED_MNEMONIC_WORDS - 1;
    output_length += space_count;

    const size_t output_size = output_length + 1;
    *output = (char*) malloc(output_size * sizeof(char));
    if (*output == NULL)
        return out_of_memory;

    (*output)[0] = '\0';

    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        const char* word = MIST_MNEMONIC_SENTENCE[index];
        const size_t word_length = strlen(word);
        const size_t word_size = word_length + 1;

        if (index != MIST_SEED_MNEMONIC_WORDS - 1) { //Unless it's the last index, append space.
            char space_trailed[word_size + strlen(MIST_SEED_MNEMONIC_SPACE)];
            strcpy(space_trailed, word);
            strcat(space_trailed, MIST_SEED_MNEMONIC_SPACE);

            strcat(*output, space_trailed);
        } else {
            strcat(*output, word);
        }
    }

    return success;
}

result MIST_GENERATE_SEED(
    unsigned char* output,
    const size_t output_size,

    char** MIST_SEED_MNEMONIC_SENTENCE
) {
    assert(output_size == MIST_SEED_SIZE);

    char* mnemonic_sentence;
    size_t mnemonic_sentence_length = 0;
    result join_result = MIST_JOIN_MNEMONIC_SENTENCE(&mnemonic_sentence, mnemonic_sentence_length, MIST_SEED_MNEMONIC_SENTENCE);
    if (join_result != success)
        return join_result;

    const unsigned char salt[crypto_pwhash_SALTBYTES] = "mnemonic";
    if(crypto_pwhash(
        output,
        MIST_SEED_SIZE,
        (const char*) mnemonic_sentence,
        strlen(mnemonic_sentence),
        (const unsigned char*) salt, //Defined at constants.h
        crypto_pwhash_OPSLIMIT_INTERACTIVE, //This will be replaced with the protocol standard.
        crypto_pwhash_MEMLIMIT_INTERACTIVE, //This will be replaced with the protocol standard.
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0)
        return out_of_memory;

    sodium_memzero(mnemonic_sentence, strlen(mnemonic_sentence) + 1);
    sodium_memzero(&mnemonic_sentence_length, sizeof(mnemonic_sentence_length));

    return success;
}

result MIST_ENCRYPT_SEED(
    unsigned char** output,
    unsigned long long output_length,
    unsigned char** MIST_NONCE_OUTPUT,
    unsigned char** MIST_SALT_OUTPUT,

    const unsigned char* MIST_SEED,
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
) { //Don't forget to wipe your MIST_SEED and MIST_PASSPHRASE variables upon usage!
    unsigned long long encryption_key_length = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
    unsigned char encryption_key[encryption_key_length];

    randombytes_buf(&MIST_NONCE_OUTPUT, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(&MIST_SALT_OUTPUT, crypto_pwhash_SALTBYTES);
    if (crypto_pwhash(
        encryption_key,
        encryption_key_length,
        MIST_PASSPHRASE,
        passphrase_length,
        *MIST_SALT_OUTPUT,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    ) != 0) {
        sodium_memzero(encryption_key, encryption_key_length);

        return seed_hashing_error;
    }

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
        *output,
        &output_length,
        MIST_SEED,
        MIST_SEED_SIZE, //Defined at constants.h
        NULL,
        0,
        NULL,
        *MIST_NONCE_OUTPUT,
        encryption_key
    ) != 0) {
        sodium_memzero(encryption_key, encryption_key_length);

        return seed_encryption_error;
    }

    sodium_memzero(encryption_key, encryption_key_length);

    return success;
}

result MIST_DECRYPT_SEED(
    unsigned char** output,
    unsigned long long output_length,

    const unsigned char* MIST_NONCE,
    const unsigned char* MIST_SALT,
    const unsigned char* MIST_CIPHERTEXT,
    const long long ciphertext_length,
    const char* MIST_PASSPHRASE,
    const size_t passphrase_length
) { //Don't forget to wipe your MIST_PASSPHRASE variable!
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
        *output,
        &output_length,
        NULL,
        MIST_CIPHERTEXT,
        ciphertext_length,
        NULL,
        0,
        MIST_NONCE,
        encryption_key
    ) != 0) {
        sodium_memzero(encryption_key, encryption_key_length);

        return seed_decryption_error;
    }

    sodium_memzero(encryption_key, encryption_key_length);

    return success;
}

result MIST_RESTORE_IDENTITY(
    char** MIST_ADDRESS_output, //Don't forget to free(). crypto_sign_ed25519_PUBLICKEYBYTES
    unsigned char* MIST_IDENTITY_PK_output, //crypto_sign_ed25519_PUBLICKEYBYTES
    unsigned char* MIST_IDENTITY_SK_output, //crypto_sign_ed25519_SECRETKEYBYTES

    const unsigned char* MIST_SEED
) {
    crypto_sign_seed_keypair(MIST_IDENTITY_PK_output, MIST_IDENTITY_SK_output, MIST_SEED);

    result encode_result = MIST_BECH32M_ENCODE(
        MIST_ADDRESS_output,
        MIST_BECH32M_HRP,
        MIST_IDENTITY_PK_output,
        crypto_sign_ed25519_PUBLICKEYBYTES
    );
    if (encode_result != success)
        return encode_result;

    return success;
}

result MIST_GENERATE_SUBKEY(
    unsigned char* MIST_SUB_PK_output, //crypto_sign_ed25519_PUBLICKEYBYTES for Ed25519, crypto_scalarmult_curve25519_BYTES for Curve25519.
    unsigned char* MIST_SUB_SK_output, //crypto_sign_ed25519_SECRETKEYBYTES for Ed25519, crypto_scalarmult_curve25519_BYTES for Curve25519.

    const unsigned char* MIST_SEED, //MIST_SEED_SIZE
    const char* MIST_CONTEXT,
    const subkey_algorithm MIST_ALGORITHM //Defined at constants.h
) {
    unsigned char prk[crypto_kdf_hkdf_sha512_KEYBYTES];
    unsigned char derived[MIST_SUBKEY_SEED_SIZE];

    crypto_kdf_hkdf_sha512_extract(
        prk,
        NULL,
        0,
        MIST_SEED,
        MIST_SEED_SIZE
    );
    crypto_kdf_hkdf_sha512_expand(
        derived,
        sizeof(derived),
        MIST_CONTEXT,
        strlen(MIST_CONTEXT),
        prk
    );

    switch (MIST_ALGORITHM) {
        case ed25519:
            crypto_sign_seed_keypair(
                MIST_SUB_PK_output,
                MIST_SUB_SK_output,
                derived
            );

            return success;
        case x25519:
            crypto_box_seed_keypair(
                MIST_SUB_PK_output,
                MIST_SUB_SK_output,
                derived
            );

            return success;
        default:
            return invalid_subkey_type;
    }

    return success;
}
