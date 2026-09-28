#include "pqxdh.h"

#include <math.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xeddsa.h>

#include "constants.h"
#include "helpers.h"
#include "identity.h"

result mist_pqxdh_initiator_prekeys_ek_rotate(
    mist_pqxdh_initiator_prekeys* initiator_prekeys,

    const uint32_t identifier
) {
    mist_subkey_key_agreement_generate(&initiator_prekeys->ek, identifier);

    return success;
}

result mist_pqxdh_recipient_prekeys_spk_rotate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const uint32_t identifier
) {
    mist_subkey_key_agreement_generate(&recipient_prekeys->spk, identifier);
    mist_key_key_agreement_sign(
        recipient_prekeys->spk_signature,
        recipient_prekeys->identity.key,
        recipient_prekeys->spk.public_key,
        sizeof(recipient_prekeys->spk.public_key)
    );

    return success;
}

result mist_pqxdh_recipient_prekeys_pqspk_rotate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const uint32_t identifier
) {
    mist_subkey_key_encapsulation_generate(&recipient_prekeys->pqspk, identifier);
    mist_key_key_agreement_sign(
        initiator_prekeys->spk_signature,
        initiator_prekeys->identity.key,
        initiator_prekeys->spk.public_key,
        sizeof(initiator_prekeys->spk.public_key),
    );

    return success;
}

result mist_pqxdh_initiator_prekeys_generate(
    mist_pqxdh_initiator_prekeys* initiator_prekeys,

    const mist_identity identity,
    const uint32_t ek_identifier
) {
    *initiator_prekeys = (mist_pqxdh_initiator_prekeys) {0};
    initiator_prekeys->identity = identity;

    mist_pqxdh_initiator_prekeys_ek_rotate(initiator_prekeys, ek_identifier);

    return success;
}

result mist_pqxdh_recipient_prekeys_generate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const mist_identity identity,
    const uint32_t spk_identifier,
    const uint32_t pqspk_identifier
) {
    *recipient_prekeys = (mist_pqxdh_recipient_prekeys) {0};
    recipient_prekeys->identity = identity;

    mist_pqxdh_recipient_prekeys_spk_rotate(recipient_prekeys, spk_identifier);
    mist_pqxdh_recipient_prekeys_pqspk_rotate(recipient_prekeys, pqspk_identifier);

    return success;
}

result mist_pqxdh_recipient_prekeys_verify(
    const mist_pqxdh_recipient_prekeys recipient_prekeys
) {
    if (mist_key_signing_verify(
        recipient_prekeys.identity.public_key,
        recipient_prekeys.spk_signature,
        sizeof(recipient_prekeys.spk_signature)
    ) != success)
        return incorrect_signature;

    if (mist_key_signing_verify(
        recipient_prekeys.identity.public_key,
        recipient_prekeys.pqspk_signature,
        sizeof(recipient_prekeys.pqspk_signature)
    ) != success)
        return incorrect_signature;

    return success;
}

result mist_pqxdh_shared_key( //To-do: Seperate initiator and recipient SK derivation
    unsigned char* ciphertext_output,
    unsigned char* shared_key_output,

    const mist_pqxdh_initiator_prekeys initiator_prekeys,
    const mist_pqxdh_recipient_prekeys recipient_prekeys,
    const uint32_t identifier
) {
    unsigned char ciphertext[MIST_MLKEM768_CT_SIZE];
    unsigned char shared_secret[MIST_MLKEM768_SS_SIZE];
    if (mist_key_key_encapsulation_encapsulate(
        ciphertext,
        shared_secret,
        recipient_prekeys.pqspk.key
    ) != 0)
        return shared_secret_generation_error;

    unsigned char dh1[MIST_DH_OUTPUT_SIZE];
    unsigned char dh2[MIST_DH_OUTPUT_SIZE];
    unsigned char dh3[MIST_DH_OUTPUT_SIZE];

    result dh_result = mist_key_key_agreement_dh(
        dh1,
        initiator_prekeys.identity.secret_key,
        recipient_prekeys.spk.key
    );
    if (dh_result != success)
        return dh_result;

    dh_result = mist_key_key_agreement_dh(
        dh2,
        initiator_prekeys.ek.key->secret_key,
        recipient_prekeys.identity.public_key
    );
    if (dh_result != success)
        return dh_result;

    dh_result = mist_key_key_agreement_dh(
        dh3,
        initiator_prekeys.ek.key->secret_key,
        recipient_prekeys.spk.key->public_key
    );
    if (dh_result != success)
        return dh_result;

    const unsigned char f[MIST_PQXDH_F_SIZE] = MIST_PQXDH_SK_F;

    unsigned char prk[crypto_kdf_hkdf_sha512_KEYBYTES];

    crypto_kdf_hkdf_sha512_state kdf_state;
    crypto_kdf_hkdf_sha512_extract_init(&kdf_state, NULL, 0);

    crypto_kdf_hkdf_sha512_extract_update(&kdf_state, f, sizeof(f));
    crypto_kdf_hkdf_sha512_extract_update(&kdf_state, dh1, sizeof(dh1));
    crypto_kdf_hkdf_sha512_extract_update(&kdf_state, dh2, sizeof(dh2));
    crypto_kdf_hkdf_sha512_extract_update(&kdf_state, dh3, sizeof(dh3));
    crypto_kdf_hkdf_sha512_extract_update(&kdf_state, shared_secret, sizeof(shared_secret));

    crypto_kdf_hkdf_sha512_extract_final(&kdf_state, prk);

    crypto_kdf_hkdf_sha512_expand(
        shared_key_output,
        MIST_PQXDH_SHARED_KEY_SIZE,
        (const char*) &identifier,
        sizeof(identifier),
        prk
    );

    memcpy(ciphertext_output, ciphertext, sizeof(ciphertext));

    return success;
}

result mist_pqxdh_associated_data(
    unsigned char* output,

    const mist_pqxdh_initiator_prekeys initiator_prekeys,
    const mist_pqxdh_recipient_prekeys recipient_prekeys
) {
    concatenate_bytes(
        output,
        initiator_prekeys.identity.public_key,
        sizeof(initiator_prekeys.identity.public_key),
        recipient_prekeys.identity.public_key,
        sizeof(recipient_prekeys.identity.public_key)
    );

    return success;
}
