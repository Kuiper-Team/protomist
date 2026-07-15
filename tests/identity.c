#include <assert.h>
#include <stdio.h>

#include <sodium.h>

#include "../source/constants.h"
#include "../source/identity.h"
#include "../source/wordlists/languages.h"

int main() {
    char* mnemonic_sentence[MIST_SEED_MNEMONIC_WORDS];
    MIST_GENERATE_MNEMONIC_SENTENCE(
        mnemonic_sentence,
        english_list
    );

    unsigned char seed[MIST_SEED_SIZE];
    MIST_GENERATE_SEED(
        seed,
        sizeof(seed),
        mnemonic_sentence
    );

    puts("Recovery Phrase:");
    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        char* word = mnemonic_sentence[index];
        assert(word != NULL);
        printf("%s ", word);
    } //Replace with sentence join function.
    puts("");

    /*
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
    */
}
