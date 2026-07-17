#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <sodium.h>

#include "../source/bech32/wrapper.h"
#include "../source/constants.h"
#include "../source/identity.h"
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
    MIST_MNEMONIC_SENTENCE_JOIN(&recovery_phrase, recovery_phrase_length, mnemonic_sentence);

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
    unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
    unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
    MIST_RESTORE_IDENTITY(
        &address,
        ed25519_pk,
        ed25519_sk,
        curve25519_pk,
        curve25519_sk,

        seed
    );

    char* ed25519_pk_bech32;
    char* ed25519_sk_bech32;
    char* curve25519_pk_bech32;
    char* curve25519_sk_bech32;

    MIST_BECH32M_ENCODE(&ed25519_pk_bech32, MIST_BECH32M_HRP, ed25519_pk, sizeof(ed25519_pk));
    MIST_BECH32M_ENCODE(&ed25519_sk_bech32, MIST_BECH32M_HRP_SECRET, ed25519_sk, sizeof(ed25519_sk));
    MIST_BECH32M_ENCODE(&curve25519_pk_bech32, MIST_BECH32M_HRP, curve25519_pk, sizeof(curve25519_pk));
    MIST_BECH32M_ENCODE(&curve25519_sk_bech32, MIST_BECH32M_HRP_SECRET, curve25519_sk, sizeof(curve25519_sk));

    printf("Address: %s\n", address);
    printf("Ed25519 Public Key: %s\n", ed25519_pk_bech32);
    printf("Ed25519 Secret Key: %s\n", ed25519_sk_bech32);
    printf("Curve25519 Public Key: %s\n", curve25519_pk_bech32);
    printf("Curve25519 Secret Key: %s\n", curve25519_sk_bech32);

    free(address);
    free(ed25519_pk_bech32);
    free(ed25519_sk_bech32);
    free(curve25519_pk_bech32);
    free(curve25519_sk_bech32);
}
