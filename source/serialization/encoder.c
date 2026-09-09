#include "encoder.h"

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <Contact.h>
//#include <Message.h> //The schema isn't ready yet.
#include <Recipient-Prekey-Bundle.h>
#include "../constants.h"
#include "../pqxdh.h"
#include "../result.h"

static OCTET_STRING_t to_OCTET_STRING(
    const unsigned char* input,
    const size_t size
) {
    OCTET_STRING_t output;
    output.buf = (uint8_t *) input;
    output.size = size;

    return output;
}

static UTF8String_t to_UTF8String(
    const char* input
) {
    UTF8String_t output;
    output.buf = (uint8_t *) input;
    output.size = strlen(input); //Originally, not a null-terminated string but a subtype of OCTET STRING, thus a byte sequence.

    return output;
}

static result encode_using_der(
    unsigned char** output,
    size_t* output_size,

    const asn_TYPE_descriptor_t* type_descriptor,
    const void* form
) {
    asn_encode_to_new_buffer_result_t encoded = asn_encode_to_new_buffer(
        0,
        ATS_DER,
        type_descriptor,
        form
    );
    if (encoded.result.encoded < 0)
        return serialization_error;

    *output = (unsigned char*) encoded.buffer;
    *output_size = (size_t) encoded.result.encoded; //The original value is a ssize_t.

    return success;
}

result MIST_SERIALIZE_CONTACT(
    unsigned char** output,
    size_t* output_size,

    const char* MIST_LABEL,
    const char* MIST_MEMO,
    const struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE
) {
    Contact_t contact = {0};

    Recipient_Prekey_Bundle_t prekey_bundle = {0};
    prekey_bundle.identity_pk = to_OCTET_STRING(MIST_PREKEY_BUNDLE->MIST_IK_PK, crypto_sign_ed25519_PUBLICKEYBYTES);
    prekey_bundle.pqspk = to_OCTET_STRING(MIST_PREKEY_BUNDLE->MIST_SPK_PK, crypto_box_PUBLICKEYBYTES);
    prekey_bundle.spk = to_OCTET_STRING(MIST_PREKEY_BUNDLE->MIST_PQSPK_PK, crypto_kem_mlkem768_PUBLICKEYBYTES);
    prekey_bundle.spk_identifier = to_UTF8String(MIST_PREKEY_BUNDLE->MIST_SPK_IDENTIFIER);
    prekey_bundle.pqspk_identifier = to_UTF8String(MIST_PREKEY_BUNDLE->MIST_PQSPK_IDENTIFIER);
    prekey_bundle.spk_signature = to_OCTET_STRING(MIST_PREKEY_BUNDLE->MIST_SPK_SIGNATURE, MIST_XEDDSA_SIGNATURE_SIZE);
    prekey_bundle.pqspk_signature = to_OCTET_STRING(MIST_PREKEY_BUNDLE->MIST_PQSPK_SIGNATURE, MIST_XEDDSA_SIGNATURE_SIZE);

    contact.label = to_UTF8String(MIST_LABEL);
    contact.memo = to_UTF8String(MIST_MEMO);
    contact.prekey_bundle = prekey_bundle;

    result encoding_result = encode_using_der(
        output,
        output_size,
        &asn_DEF_Contact,
        &contact
    );
    if (encoding_result != success)
        return encoding_result;

    return success;
}
