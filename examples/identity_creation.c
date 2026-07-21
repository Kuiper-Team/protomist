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

    printf("\n-- IDENTITY --\n");

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

    printf("\n-- CONTACT --\n");

    char* contact_block;
    const char* label = "Me";
    const char* memo = "This is my profile.\nThis line proves that multiline memos are supported.\nEven more proof.";
    MIST_CREATE_CONTACT_BLOCK(
        &contact_block,
        address,
        "Me",
        memo
    );

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
    assert(strcmp(label_test, label) == 0);
    assert(strcmp(memo_test, memo) == 0);

    printf("Label: %s\nMemo: %s\nBlock: %s\n", label_test, memo_test, contact_block);

    //RELOCATE AFTER DEBUGGING

    free(address_test);
    free(label_test);
    free(memo_test);

    free(address);
    free(contact_block);
}
