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
    memcpy(secrets_output->MIST_IK_SK, MIST_INITIATOR_IK_SK, crypto_sign_ed25519_SECRETKEYBYTES); //The size must be appropriate.

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
    memcpy(secrets_output->MIST_IK_SK, MIST_RECIPIENT_IK_SK, crypto_sign_ed25519_SECRETKEYBYTES); //The size must be appropriate.

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

    //XEdDSA signature creation here.
    //EncodeEC() & EncodeKEM()

    sodium_memzero(MIST_Z_SPK, sizeof(MIST_Z_SPK));
    sodium_memzero(MIST_Z_PQSPK, sizeof(MIST_Z_PQSPK));

    return success;
}

result MIST_VERIFY_RECIPIENT_PREKEY_BUNDLE( //WIP
    const struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE
) {
    const unsigned char* ik = MIST_PREKEY_BUNDLE->MIST_IK_PK;

    const unsigned char* spk_signature = MIST_PREKEY_BUNDLE->MIST_SPK_SIGNATURE;
    const unsigned char* pqspk_signature = MIST_PREKEY_BUNDLE->MIST_PQSPK_SIGNATURE;

    //XEdDSA signature verification here.

    return success;
}

result MIST_CALCULATE_SHARED_KEY( //Rename for clarity? //Combines (CT, SS) generation and SK = KDF(...) //WIP
    unsigned char* output,
    unsigned char* MIST_CIPHERTEXT_output, //crypto_kem_mlkem768_CIPHERTEXTBYTES
    unsigned char* MIST_SHARED_KEY_output, //MIST_SUBKEY_SEED_SIZE

    const struct initiator_prekey_bundle* MIST_INITIATOR_PREKEY_BUNDLE,
    const struct initiator_prekey_secrets* MIST_INITIATOR_PREKEY_SECRETS,
    const struct recipient_prekey_bundle* MIST_RECIPIENT_PREKEY_BUNDLE,
    const size_t MIST_IDENTIFIER_NUMBER
) {
    unsigned char* shared_secret;
    if (crypto_kem_mlkem768_enc(
        MIST_CIPHERTEXT_output,
        shared_secret,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_PQSPK_PK
    ) != 0)
        return shared_secret_generation_error;

    unsigned char dh1[MIST_SUBKEY_SEED_SIZE];
    unsigned char dh2[MIST_SUBKEY_SEED_SIZE];
    unsigned char dh3[MIST_SUBKEY_SEED_SIZE];

    crypto_kx_client_session_keys(
        dh1,
        NULL,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_IK_PK,
        MIST_INITIATOR_PREKEY_SECRETS->MIST_IK_SK,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_SPK_PK
    );
    crypto_kx_client_session_keys(
        dh2,
        NULL,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_EK_PK,
        MIST_INITIATOR_PREKEY_SECRETS->MIST_EK_SK,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_IK_PK
    );
    crypto_kx_client_session_keys(
        dh3,
        NULL,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_EK_PK,
        MIST_INITIATOR_PREKEY_SECRETS->MIST_EK_SK,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_SPK_PK
    );

    const size_t identifier_number_digits = count_digits(MIST_IDENTIFIER_NUMBER); 
    const size_t identifier_size = strlen(MIST_SK_IDENTIFIER_PREFIX) + identifier_number_digits + 1;

    char identifier_number_string[identifier_number_digits + 1];
    snprintf(
        identifier_number_string,
        sizeof(identifier_number_string),
        "%zu",
        MIST_IDENTIFIER_NUMBER
    );

    char* identifier = (char*) malloc(identifier_size);
    if (identifier == NULL)
        return out_of_memory;

    strcpy(output->MIST_SPK_IDENTIFIER, MIST_SPK_IDENTIFIER_PREFIX);
    strcat(output->MIST_SPK_IDENTIFIER, identifier_number_string);

    unsigned char f[MIST_SK_F_SIZE] = MIST_SK_F;
    unsigned char km[crypto_kdf_hkdf_sha512_KEYBYTES]; //TO-DO: Concatenate dh1, dh2, dh3 and shared_secret. In order to do so, modify concatenate_bytes() to become a variadic, general-purpose helper.

    unsigned char ikm[sizeof(f) + sizeof(km)];
    concatenate_bytes(
        &ikm,
        f,
        sizeof(f),
        km,
        sizeof(km)
    );

    unsigned char derived[MIST_SUBKEY_SEED_SIZE];
    crypto_kdf_hkdf_sha512_extract(
        irk,
        NULL,
        0,
        ikm,
        sizeof(ikm)
    );
    crypto_kdf_hkdf_sha512_expand(
        derived,
        sizeof(derived),
        identifier,
    );

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

    const struct initiator_prekey_bundle* MIST_PREKEY_BUNDLE
    const unsigned char* MIST_CIPHERTEXT
) {
    return success;
}
