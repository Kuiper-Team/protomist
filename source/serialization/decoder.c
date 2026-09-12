#include "decoder.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <Contact.h>
#include <Recipient-Prekey-Bundle.h>
#include "../pqxdh.h"
#include "../result.h"

static result from_OCTET_STRING(
    unsigned char** output,
    size_t* output_size, //Optional, pass NULL if not needed.

    const OCTET_STRING_t input
) {
    const size_t size = input.size;
    *output = malloc(size * sizeof(**output));
    if (*output == NULL)
        return out_of_memory;

    memcpy(*output, (unsigned char*) input.buf, size);

    if (output_size != NULL)
        *output_size = size;

    return success;
}

static result from_UTF8String(
    char** output,
    size_t* output_size, //Optional, pass NULL if not needed.

    const UTF8String_t input
) {
    const size_t length = input.size;
    const size_t size = length + 1;
    *output = malloc(size * sizeof(**output));
    if (*output == NULL)
        return out_of_memory;

    const size_t last_index = size - 1;
    strncpy(*output, (char*) input.buf, length);
    (*output)[last_index] = '\0';

    if (output_size != NULL)
        *output_size = size;

    return success;
}

result MIST_DESERIALIZE_CONTACT(
    char** MIST_LABEL_output,
    char** MIST_MEMO_output,
    struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE_output,

    const unsigned char* MIST_ENCODED,
    const size_t MIST_ENCODED_size
) {
    Contact_t* contact = {0};

    asn_dec_rval_t decoding_result = ber_decode(
        0,
        &asn_DEF_Contact,
        (void**) &contact,
        MIST_ENCODED,
        MIST_ENCODED_size
    );
    if (decoding_result.code != RC_OK)
        return deserialization_error;

    unsigned char *ik_pk, *spk_pk, *pqspk_pk, *spk_signature, *pqspk_signature;
    char *spk_identifier, *pqspk_identifier;

    size_t ik_pk_size, spk_pk_size, pqspk_pk_size, spk_identifier_size, pqspk_identifier_size, spk_signature_size, pqspk_signature_size;

    Recipient_Prekey_Bundle_t prekey_bundle = contact->prekey_bundle;

    from_OCTET_STRING(&ik_pk, &ik_pk_size, prekey_bundle.identity_pk);
    from_OCTET_STRING(&spk_pk, &spk_pk_size, prekey_bundle.spk);
    from_OCTET_STRING(&pqspk_pk, &pqspk_pk_size, prekey_bundle.pqspk);
    from_UTF8String(&spk_identifier, &spk_identifier_size, prekey_bundle.spk_identifier);
    from_UTF8String(&pqspk_identifier, &pqspk_identifier_size, prekey_bundle.pqspk_identifier);
    from_OCTET_STRING(&spk_signature, &spk_signature_size, prekey_bundle.spk_signature);
    from_OCTET_STRING(&pqspk_signature, &pqspk_signature_size, prekey_bundle.pqspk_signature);

    if (
        ik_pk_size != MIST_ED25519_PK_SIZE ||
        spk_pk_size != MIST_X25519_PK_SIZE ||
        pqspk_pk_size != MIST_MLKEM768_PK_SIZE ||
        spk_signature_size != MIST_XEDDSA_SIGNATURE_SIZE ||
        pqspk_signature_ssize != MIST_XEDDSA_SIGNATURE_SIZE
    )
        return malformed_serialized_data;

    from_UTF8String(MIST_LABEL_output, NULL, contact->label);
    from_UTF8String(MIST_MEMO_output, NULL, contact->memo);

    memcpy(MIST_PREKEY_BUNDLE_output->MIST_IK_PK, ik_pk, ik_pk_size);
    memcpy(MIST_PREKEY_BUNDLE_output->MIST_SPK_PK, spk_pk, spk_pk_size);
    memcpy(MIST_PREKEY_BUNDLE_output->MIST_PQSPK_PK, pqspk_pk, pqspk_pk_size);
    MIST_PREKEY_BUNDLE_output->MIST_SPK_IDENTIFIER = spk_identifier;
    MIST_PREKEY_BUNDLE_output->MIST_PQSPK_IDENTIFIER = pqspk_identifier;
    memcpy(MIST_PREKEY_BUNDLE_output->MIST_SPK_SIGNATURE, spk_signature, spk_signature_size);
    memcpy(MIST_PREKEY_BUNDLE_output->MIST_PQSPK_SIGNATURE, pqspk_signature, pqspk_signature_size);

    free(ik_pk);
    free(spk_pk);
    free(pqspk_pk);
    free(spk_identifier);
    free(pqspk_identifier);
    free(spk_signature);
    free(pqspk_signature);

    return success;
}
