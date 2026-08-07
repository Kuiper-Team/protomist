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
    size_t recovery_phrase_length = 0;
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

    free(address_test);
    free(label_test);
    free(memo_test);

    free(address);
    free(contact_block);

    printf("\n-- SUBKEYS --\n");

    unsigned char example1_sub_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char example1_sub_sk[crypto_sign_ed25519_PUBLICKEYBYTES];
    result example1_sub_result = MIST_GENERATE_SUBKEY(
        example1_sub_pk,
        example1_sub_sk,
        seed,
        "example1",
        ed25519
    );

    unsigned char example2_sub_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char example2_sub_sk[crypto_sign_ed25519_PUBLICKEYBYTES];
    result example2_sub_result = MIST_GENERATE_SUBKEY(
        example2_sub_pk,
        example2_sub_sk,
        seed,
        "example2",
        x25519
    );

    assert(example1_sub_result == success && example2_sub_result == success);

    char* example1_sub_pk_bech32m;
    char* example1_sub_sk_bech32m;
    char* example2_sub_pk_bech32m;
    char* example2_sub_sk_bech32m;

    MIST_BECH32M_ENCODE(&example1_sub_pk_bech32m, MIST_BECH32M_HRP, example1_sub_pk, sizeof(example1_sub_pk));
    MIST_BECH32M_ENCODE(&example1_sub_sk_bech32m, MIST_BECH32M_HRP_SECRET, example1_sub_sk, sizeof(example1_sub_sk));
    MIST_BECH32M_ENCODE(&example2_sub_pk_bech32m, MIST_BECH32M_HRP, example2_sub_pk, sizeof(example2_sub_pk));
    MIST_BECH32M_ENCODE(&example2_sub_sk_bech32m, MIST_BECH32M_HRP_SECRET, example2_sub_sk, sizeof(example2_sub_sk));

    assert(example1_sub_pk_bech32m != NULL);
    assert(example1_sub_sk_bech32m != NULL);
    assert(example2_sub_pk_bech32m != NULL);
    assert(example2_sub_sk_bech32m != NULL);

    printf("example1:\n%s\n%s\n\nexample2:\n%s\n%s\n", example1_sub_pk_bech32m, example1_sub_sk_bech32m, example2_sub_pk_bech32m, example2_sub_sk_bech32m);
}
