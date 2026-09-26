#include "pqxdh.h"

#include <math.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xeddsa.h>

#include "constants.h"
#include "identity.h"

result mist_pqxdh_initiator_prekeys_ek_rotate(
    mist_pqxdh_initiator_prekeys* initiator_prekeys,

    const uint32_t identifier
) {
    mist_subkey_key_agreement_generate(initiator_prekeys->ek, identifier);

    return success;
}

result mist_pqxdh_recipient_prekeys_spk_rotate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const uint32_t identifier
) {
    mist_subkey_key_agreement_generate(initiator_prekeys->spk, identifier);
    mist_key_signing_sign(
        initiator_prekeys->spk_signature,
        initiator_prekeys->identity.key,
        initiator_prekeys->spk.public_key,
        sizeof(initiator_prekeys->spk.public_key),
    );

    return success;
}

result mist_pqxdh_recipient_prekeys_pqspk_rotate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const uint32_t identifier
) {
    crypto_subkey_key_encapsulation_generate(recipient_prekeys->pqspk, identifier);
    mist_key_signing_sign(
        initiator_prekeys->spk_signature,
        initiator_prekeys->identity.key,
        initiator_prekeys->spk.public_key,
        sizeof(initiator_prekeys->spk.public_key),
    );

    return success;
}

result mist_pqxdh_initiator_prekeys_generate(
    mist_pqxdh_initiator_prekeys* initiator_prekeys,

    mist_identity identity,
    const uint32_t ek_identifier
) {
    *initiator_prekeys = (mist_pqxdh_initiator_prekeys) {0};
    initiator_prekeys->identity = identity;

    mist_pqxdh_initiator_prekeys_ek_rotate(initiator_prekeys, identifier);

    return success;
}

result mist_pqxdh_recipient_prekeys_generate(
    mist_pqxdh_recipient_prekeys recipient_prekeys

    mist_identity identity,
    const uint32_t spk_identifier,
    const uint32_t pqspk_identifier
) {
    *recipient_prekeys = (mist_pqxdh_recipient_prekeys) {0};
    recipient_prekeys->identity = identity;

    mist_pqxdh_recipient_prekeys_spk_rotate(recipient_prekeys, identifier);
    mist_pqxdh_recipient_prekeys_pqspk_rotate(recipient_prekeys, identifier);

    //TO-DO: Add mist_key_signing_sign_xeddsa and use it for SPK and PQSPK rotation.
    /*
    unsigned char MIST_Z_SPK[MIST_Z_SIZE];
    unsigned char MIST_Z_PQSPK[MIST_Z_SIZE];
    randombytes_buf(MIST_Z_SPK, sizeof(MIST_Z_SPK));
    randombytes_buf(MIST_Z_PQSPK, sizeof(MIST_Z_PQSPK));

    ed25519_priv_sign(
        MIST_PREKEY_BUNDLE_output->MIST_SPK_SIGNATURE,
        MIST_PREKEY_SECRETS_output->MIST_IK_SK,
        MIST_PREKEY_BUNDLE_output->MIST_SPK_PK,
        sizeof(MIST_PREKEY_BUNDLE_output->MIST_SPK_PK),
        MIST_Z_SPK
    );
    ed25519_priv_sign(
        MIST_PREKEY_BUNDLE_output->MIST_PQSPK_SIGNATURE,
        MIST_PREKEY_SECRETS_output->MIST_IK_SK,
        MIST_PREKEY_BUNDLE_output->MIST_PQSPK_PK,
        sizeof(MIST_PREKEY_BUNDLE_output->MIST_PQSPK_PK),
        MIST_Z_PQSPK
    );

    sodium_memzero(MIST_Z_SPK, sizeof(MIST_Z_SPK));
    sodium_memzero(MIST_Z_PQSPK, sizeof(MIST_Z_PQSPK));
    */

    return success;
}

result mist_pqxdh_recipient_prekeys_verify(
    mist_pqxdh_recipient_prekeys recipient_prekeys
) {
    if (ed25519_verify(
        MIST_PREKEY_BUNDLE->MIST_SPK_SIGNATURE,
        MIST_PREKEY_BUNDLE->MIST_IK_PK,
        MIST_PREKEY_BUNDLE->MIST_SPK_PK,
        sizeof(MIST_PREKEY_BUNDLE->MIST_SPK_PK)
    ) != 0)
        return incorrect_signature;

    if (ed25519_verify(
        MIST_PREKEY_BUNDLE->MIST_PQSPK_SIGNATURE,
        MIST_PREKEY_BUNDLE->MIST_IK_PK,
        MIST_PREKEY_BUNDLE->MIST_PQSPK_PK,
        sizeof(MIST_PREKEY_BUNDLE->MIST_PQSPK_PK)
    ) != 0)
        return incorrect_signature;

    return success;
}

result mist_pqxdh_shared_key(
    unsigned char* ciphertext_output,
    unsigned char* shared_key_output,

    mist_pqxdh_initiator_prekeys initiator_prekeys,
    mist_pqxdh_recipient_prekeys recipient_prekeys
) { //Don't forget to free output->MIST_SPK_IDENTIFIER!
    char* identifier;
    size_t identifier_size;
    result identifier_result = generate_identifier(
        &identifier,
        &identifier_size,
        MIST_SK_IDENTIFIER_PREFIX,
        MIST_IDENTIFIER_NUMBER
    );
    if (identifier_result != success)
        return identifier_result;

    unsigned char shared_secret[MIST_MLKEM768_SS_SIZE];
    if (crypto_kem_mlkem768_enc(
        MIST_CIPHERTEXT_output,
        shared_secret,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_PQSPK_PK
    ) != 0)
        return shared_secret_generation_error;

    unsigned char dh1[MIST_SUBKEY_SEED_SIZE];
    unsigned char dh2[MIST_SUBKEY_SEED_SIZE];
    unsigned char dh3[MIST_SUBKEY_SEED_SIZE];

    if (crypto_kx_client_session_keys(
        dh1,
        NULL,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_IK_PK,
        MIST_INITIATOR_PREKEY_SECRETS->MIST_IK_SK,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_SPK_PK
    ) != 0)
        return key_exchange_error;

    if (crypto_kx_client_session_keys(
        dh2,
        NULL,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_EK_PK,
        MIST_INITIATOR_PREKEY_SECRETS->MIST_EK_SK,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_IK_PK
    ) != 0)
        return key_exchange_error;

    if (crypto_kx_client_session_keys(
        dh3,
        NULL,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_EK_PK,
        MIST_INITIATOR_PREKEY_SECRETS->MIST_EK_SK,
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_SPK_PK
    ) != 0)
        return key_exchange_error;

    const unsigned char f[MIST_SK_F_SIZE] = MIST_SK_F;

    const unsigned char* km_blueprint[MIST_KM_SECTIONS] = {dh1, dh2, dh3, shared_secret};
    const size_t km_sizes[MIST_KM_SECTIONS] = {sizeof(dh1), sizeof(dh2), sizeof(dh3), sizeof(shared_secret)};
    unsigned char km[sizeof(dh1) + sizeof(dh2) + sizeof(dh3) + sizeof(shared_secret)];
    build_concatenated_buffer(
        km,
        km_blueprint,
        km_sizes,
        MIST_KM_SECTIONS
    );

    unsigned char ikm[sizeof(f) + sizeof(km)];
    concatenate_bytes(
        ikm,
        f,
        sizeof(f),
        km,
        sizeof(km)
    );

    unsigned char prk[crypto_kdf_hkdf_sha512_KEYBYTES];
    crypto_kdf_hkdf_sha512_extract(
        prk,
        NULL,
        0,
        ikm,
        sizeof(ikm)
    );
    crypto_kdf_hkdf_sha512_expand(
        MIST_SHARED_KEY_output,
        MIST_SUBKEY_SEED_SIZE,
        identifier,
        identifier_size,
        prk
    );

    return success;
}

result mist_pqxdh_associated_data(
    unsigned char* output,

    mist_pqxdh_initiator_prekeys initiator_prekeys,
    mist_pqxdh_recipient_prekeys recipient_prekeys
) {
    concatenate_bytes(
        output,
        MIST_INITIATOR_PREKEY_BUNDLE->MIST_IK_PK,
        sizeof(MIST_INITIATOR_PREKEY_BUNDLE->MIST_IK_PK),
        MIST_RECIPIENT_PREKEY_BUNDLE->MIST_IK_PK,
        sizeof(MIST_RECIPIENT_PREKEY_BUNDLE->MIST_IK_PK)
    );

    return success;
}
