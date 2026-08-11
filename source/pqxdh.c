#include "pqxdh.h"

#include <math.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "helpers.h"
#include "identity.h"

static result generate_identifier(
    char** output,

    const char* prefix,
    const size_t number
) { //Don't forget to free() output!
    const size_t number_digits = count_digits(number); 
    const size_t size = strlen(prefix) + number_digits + 1;

    char number_string[number_digits + 1];
    snprintf(
        number_string,
        sizeof(number_string),
        "%zu", //Format specifier to handle size_t
        number
    );

    *output = (char*) malloc(size);
    if (*output == NULL)
        return out_of_memory;   

    strcpy(*output, prefix);
    strcat(*output, number_string);

    return success;
}

result MIST_GENERATE_INITIATOR_PREKEY_BUNDLE(
    struct initiator_prekey_bundle* MIST_PREKEY_BUNDLE_output,
    struct initiator_prekey_secrets* MIST_PREKEY_SECRETS_output,

    const unsigned char* MIST_INITIATOR_IK_PK
) {
    memcpy(MIST_PREKEY_BUNDLE_output->MIST_IK_PK, MIST_INITIATOR_IK_PK, crypto_sign_ed25519_PUBLICKEYBYTES); //The size must be appropriate.
    memcpy(MIST_PREKEY_SECRETS_output->MIST_IK_SK, MIST_INITIATOR_IK_SK, crypto_sign_ed25519_SECRETKEYBYTES); //The size must be appropriate.

    crypto_box_keypair(
        MIST_PREKEY_BUNDLE_output->MIST_EK_PK,
        MIST_PREKEY_SECRETS_output->MIST_EK_SK
    );

    return success;
}

result MIST_GENERATE_RECIPIENT_PREKEY_BUNDLE( //WIP
    struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE_output,
    struct recipient_prekey_secrets* MIST_PREKEY_SECRETS_output,

    const unsigned char* MIST_RECIPIENT_IK_PK,
    const unsigned char* MIST_RECIPIENT_IK_SK,
    const size_t MIST_IDENTIFIER_NUMBER
) { //Don't forget to free() output->MIST_SPK_IDENTIFIER!
    memcpy(MIST_PREKEY_BUNDLE_output->MIST_IK_PK, MIST_RECIPIENT_IK_PK, crypto_sign_ed25519_PUBLICKEYBYTES); //The size must be appropriate.
    memcpy(MIST_PREKEY_SECRETS_output->MIST_IK_SK, MIST_RECIPIENT_IK_SK, crypto_sign_ed25519_SECRETKEYBYTES); //The size must be appropriate.

    const size_t identifier_number_digits = count_digits(MIST_IDENTIFIER_NUMBER); 
    const size_t identifier_size = strlen(MIST_SPK_IDENTIFIER_PREFIX) + identifier_number_digits + 1;

    result identifier_result;

    identifier_result = generate_identifier(
        &MIST_PREKEY_BUNDLE_output->MIST_SPK_IDENTIFIER,
        MIST_SPK_IDENTIFIER_PREFIX,
        MIST_IDENTIFIER_NUMBER
    );
    if (identifier_result != success)
        return identifier_result;

    identifier_result = generate_identifier(
        &MIST_PREKEY_BUNDLE_output->MIST_PQSPK_IDENTIFIER,
        MIST_PQSPK_IDENTIFIER_PREFIX,
        MIST_IDENTIFIER_NUMBER
    );
    if (identifier_result != success)
        return identifier_result;

    MIST_GENERATE_SUBKEY(
        MIST_PREKEY_BUNDLE_output->MIST_SPK_PK,
        MIST_PREKEY_SECRETS_output->MIST_SPK_SK,
        MIST_RECIPIENT_IK_PK,
        MIST_PREKEY_BUNDLE_output->MIST_SPK_IDENTIFIER,
        x25519
    );

    unsigned char MIST_Z_SPK[MIST_Z_SIZE];
    unsigned char MIST_Z_PQSPK[MIST_Z_SIZE];
    randombytes_buf(MIST_Z_SPK, sizeof(MIST_Z_SPK));
    randombytes_buf(MIST_Z_PQSPK, sizeof(MIST_Z_PQSPK));

    //XEdDSA signature creation here.
    //EncodeEC() & EncodeKEM()

    //Important: Do we keep them as secrets, or wipe them?
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
    unsigned char* MIST_CIPHERTEXT_output, //crypto_kem_mlkem768_CIPHERTEXTBYTES
    unsigned char* MIST_SHARED_KEY_output, //MIST_SUBKEY_SEED_SIZE

    const struct initiator_prekey_bundle* MIST_INITIATOR_PREKEY_BUNDLE,
    const struct initiator_prekey_secrets* MIST_INITIATOR_PREKEY_SECRETS,
    const struct recipient_prekey_bundle* MIST_RECIPIENT_PREKEY_BUNDLE,
    const size_t MIST_IDENTIFIER_NUMBER
) { //Don't forget to free output->MIST_SPK_IDENTIFIER!
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

    const unsigned char f[MIST_SK_F_SIZE] = MIST_SK_F;

    const unsigned char* km_blueprint[MIST_KM_SECTIONS] = {dh1, dh2, dh3, shared_secret};
    const size_t km_sizes[MIST_KM_SECTIONS] = {sizeof(dh1), sizeof(dh2), sizeof(dh3), sizeof(shared_secret)};
    unsigned char* km;
    build_concatenated_buffer(
        &km,
        km_blueprint,
        km_sizes,
        MIST_KM_SECTIONS
    );

    unsigned char* ikm;
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

result MIST_CALCULATE_ASSOCIATED_DATA(
    unsigned char* output,

    const struct initiator_prekey_bundle* MIST_INITIATOR_PREKEY_BUNDLE,
    const struct recipient_prekey_bundle* MIST_RECIPIENT_PREKEY_BUNDLE
) {
    concatenate_bytes(
        output,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_INITIATOR_IK,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_RECIPIENT_IK
    );

    return success;
}

result MIST_SERIALIZE_INITIAL_PAYLOAD( //Needs a better name. //WIP
    unsigned char* output,

    const struct initiator_prekey_bundle* MIST_PREKEY_BUNDLE,
    const unsigned char* MIST_CIPHERTEXT
) {
    //An initial ciphertext encrypted with some AEAD scheme using AD as associated data and using SK as the encryption key.

    return success;
}
