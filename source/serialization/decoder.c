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

    const OCTET_STRING_t input
) {
    const size = input.size;
    *output = malloc(size * sizeof(unsigned char));
    if (*output == NULL)
        return out_of_memory;

    memcpy(*output, input.buf, size);

    return success;
}

static result from_UTF8String(
    char** output,

    const UTF8String_t input
) {
    const size_t length = input.size;
    const size_t size = length + 1;
    *output = malloc(size * sizeof(char));
    if (*output == NULL)
        return out_of_memory;

    const size_t null_terminator_index = size - 1;
    memcpy(*output, input.buf, length);
    (*output)[null_terminator_index] = '\0';

    return success;
}

result MIST_DESERIALIZE_CONTACT(
    char** MIST_LABEL_output,
    char** MIST_MEMO_output,
    recipient_prekey_bundle* MIST_PREKEY_BUNDLE_output,

    const unsigned char* MIST_ENCODED,
    const size_t MIST_ENCODED_size
) {
    Contact_t* contact = {0};

    decoding_result = ber_decode(
        0,
        &asn_DEF_Contact,
        (void**) &contact,
        MIST_ENCODED,
        MIST_ENCODED_size
    );
    if (decoding_result.code != RC_OK)
        return deserialization_error;

    unsigned char *ik_pk, *spk_pk, *pqspk_pk, *spk_signature, *pqspk_signature;
    char *spk_identifier, pqspk_identifier;

    recipient_prekey_bundle* prekey_bundle = contact->prekey_bundle;
    from_OCTET_STRING(&ik_pk, prekey_bundle->identity_pk);
    from_OCTET_STRING(&pqspk_pk, prekey_bundle->spk);
    from_OCTET_STRING(&ik_pk, prekey_bundle->pqspk);
    from_UTF8String(&spk_identifier, contact->spk_identifier);
    from_UTF8String(&pqspk_identifier, contact->pqspk_identifier);
    from_OCTET_STRING(&spk_signature, prekey_bundle->identity_pk);
    from_OCTET_STRING(&pqspk_signature, prekey_bundle->identity_pk);

    from_UTF8String(&MIST_LABEL_output, contact->label);
    from_UTF8String(&MIST_MEMO_output, contact->memo);
    *MIST_PREKEY_BUNDLE_output = (recipient_prekey_bundle) {
        .MIST_IK_PK = ik_pk,
        .MIST_SPK_PK = spk_pk,
        .MIST_PQSPK_PK = pqspk_pk,
        .MIST_SPK_IDENTIFIER = spk_identifier,
        .MIST_PQSPK_IDENTIFIER = pqspk_identifier,
        .MIST_SPK_SIGNATURE = spk_signature,
        .MIST_PQSPK_SIGNATURE = pqspk_signature
    }


    return success;
}
