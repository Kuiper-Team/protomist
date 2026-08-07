#include "pqxdh.h"

#include <math.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "helpers.h"
#include "identity.h"

result MIST_GENERATE_INITIATOR_PREKEY_BUNDLE(
    struct initiator_prekey_bundle* output,
    struct initiator_prekey_secrets* secrets_output,

    const unsigned char* MIST_INITIATOR_IK_PK
) {
    memcpy(output->MIST_IK_PK, MIST_INITIATOR_IK_PK, crypto_sign_ed25519_PUBLICKEYBYTES); //The size must be appropriate.

    crypto_box_keypair(
        output->MIST_EK_PK,
        secrets_output->MIST_EK_SK
    );

    return success;
}

result MIST_GENERATE_RECIPIENT_PREKEY_BUNDLE( //WIP
    struct recipient_prekey_bundle* output,
    struct recipient_prekey_secrets* secrets_output,

    const unsigned char* MIST_RECIPIENT_IK_PK,
    const unsigned char* MIST_RECIPIENT_IK_SK,
    const size_t MIST_IDENTIFIER_NUMBER
) { //Don't forget to free() output->MIST_SPK_IDENTIFIER!
    memcpy(output->MIST_IK_PK, MIST_RECIPIENT_IK_PK, crypto_sign_ed25519_PUBLICKEYBYTES); //The size must be appropriate.

    const size_t identifier_number_digits = count_digits(MIST_IDENTIFIER_NUMBER); 
    const size_t identifier_size = strlen(MIST_SPK_IDENTIFIER_PREFIX) + identifier_number_digits + 1;

    char identifier_number_string[identifier_number_digits + 1];
    snprintf(
        identifier_number_string,
        sizeof(identifier_number_string),
        "%zu",
        MIST_IDENTIFIER_NUMBER
    );

    output->MIST_SPK_IDENTIFIER = (char*) malloc(identifier_size);
    if (output->MIST_SPK_IDENTIFIER == NULL)
        return out_of_memory;

    strcpy(output->MIST_SPK_IDENTIFIER, MIST_SPK_IDENTIFIER_PREFIX);
    strcat(output->MIST_SPK_IDENTIFIER, identifier_number_string);

    MIST_GENERATE_SUBKEY(
        output->MIST_SPK_PK,
        secrets_output->MIST_SPK_SK,
        MIST_RECIPIENT_IK_PK,
        output->MIST_SPK_IDENTIFIER,
        x25519
    );

    unsigned char MIST_Z_SPK[MIST_Z_SIZE];
    unsigned char MIST_Z_PQSPK[MIST_Z_SIZE];
    randombytes_buf(MIST_Z_SPK, sizeof(MIST_Z_SPK));
    randombytes_buf(MIST_Z_PQSPK, sizeof(MIST_Z_PQSPK));

    //To-do: Signatures.

    sodium_memzero(MIST_Z_SPK, sizeof(MIST_Z_SPK));
    sodium_memzero(MIST_Z_PQSPK, sizeof(MIST_Z_PQSPK));

    return success;
}

result MIST_VERIFY_RECIPIENT_PREKEY_BUNDLE(
    const struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE
) { //WIP
    return success;
}

result MIST_CALCULATE_SHARED_KEY( //WIP
    unsigned char* output,
    unsigned char* MIST_CIPHERTEXT_output,

    const unsigned char* MIST_INITIATOR_IK,
    const unsigned char* MIST_RECIPIENT_IK,
    const unsigned char* MIST_RECIPIENT_SPK,
    const unsigned char* MIST_RECIPIENT_EK,
    const unsigned char* MIST_SHARED_SECRET
) {
    return success;
}

result MIST_CALCULATE_ASSOCIATED_DATA( //WIP
    unsigned char* output,

    const unsigned char* MIST_INITIATOR_IK,
    const unsigned char* MIST_RECIPIENT_IK
) {
    return success;
}

result MIST_SERIALIZE_INITIAL_PAYLOAD( //WIP
    unsigned char* output,

    const unsigned char* MIST_IK,
    const unsigned char* MIST_EPK,
    const unsigned char* MIST_CIPHERTEXT
) {
    return success;
}
