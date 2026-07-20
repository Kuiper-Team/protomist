#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "../source/bech32/wrapper.h"
#include "../source/constants.h"
#include "../source/contacts.h"
#include "../source/identity.h"
#include "../source/result.h"
#include "../source/wordlists/languages.h"

int main() {
    if (sodium_init() == -1) {
        fprintf(stderr, "ERROR: libsodium could not be initialized.");

        exit(1);
    }

    char* mnemonic_sentence[MIST_SEED_MNEMONIC_WORDS];
    MIST_GENERATE_MNEMONIC_SENTENCE(
        mnemonic_sentence,
        english_list
    );

    char* recovery_phrase;
    size_t recovery_phrase_length;
    MIST_JOIN_MNEMONIC_SENTENCE(&recovery_phrase, recovery_phrase_length, mnemonic_sentence);

    printf("Recovery Phrase: %s\n", recovery_phrase);
    free(recovery_phrase);
 
    unsigned char seed[MIST_SEED_SIZE];
    MIST_GENERATE_SEED(
        seed,
        sizeof(seed),
        mnemonic_sentence
    );

    char* address;
    unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
    MIST_RESTORE_IDENTITY(
        &address,
        ed25519_pk,
        ed25519_sk,

        seed
    );

    unsigned char* address_to_pk;
    result result1 = MIST_BECH32M_DECODE(&address_to_pk, address);

    assert(result1 == success);
    assert(
        memcmp(
            address_to_pk,
            ed25519_pk,
            crypto_sign_ed25519_PUBLICKEYBYTES
        ) == 0
    );

    char* ed25519_sk_bech32;
    MIST_BECH32M_ENCODE(&ed25519_sk_bech32, MIST_BECH32M_HRP_SECRET, ed25519_sk, sizeof(ed25519_sk));

    printf("Address: %s\n", address);
    printf("Ed25519 Secret Key: %s\n", ed25519_sk_bech32);

    sodium_memzero(ed25519_sk_bech32, sizeof(ed25519_sk));
    free(ed25519_sk_bech32);

    char* contact_block;
    MIST_CREATE_CONTACT_BLOCK(
        &contact_block,
        address,
        "Me",
        "This is my profile."
    );

    printf("Contact Block:\n%s\n", contact_block);

    char* address_test;
    char* label_test;
    char* memo_test;
    result result2 = MIST_DECODE_CONTACT_BLOCK(
        &address_test,
        &label_test,
        &memo_test,
        contact_block
    );

    assert(result2 == success);
    assert(strcmp(address_test, address) == 0);
    assert(strcmp(label_test, "Me") == 0);
    assert(strcmp(memo_test, "This is my profile.") == 0);

    free(address_test);
    free(label_test);
    free(memo_test);

    free(address);
    free(contact_block);
}
