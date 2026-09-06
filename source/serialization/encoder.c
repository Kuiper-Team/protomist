#include "encoder.h"

#include <sodium.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "generated/Contact.h"
#include "generated/Message.h"
#include "generated/Recipient-Prekey-Bundle.h"
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
    output.size = strlen(input); //Not a null-terminated string originally.

    return output;
}

result MIST_ENCODE_CONTACT_SCHEMA(
    unsigned char** output,
    size_t* output_size,

    const char* label,
    const char* memo,
    const recipient_prekey_bundle* prekey_bundle
) {
    Contact_t contact = {0};

    Recipient_Prekey_Bundle_t prekey_bundle_asn1c = {0};
    prekey_bundle_asn1c.identity_pk = to_OCTET_STRING(prekey_bundle->MIST_IK_PK, crypto_sign_ed25519_PUBLICKEYBYTES);
    prekey_bundle_asn1c.pqspk = to_OCTET_STRING(prekey_bundle->MIST_SPK_PK, crypto_box_PUBLICKEYBYTES);
    prekey_bundle_asn1c.spk = to_OCTET_STRING(prekey_bundle->MIST_PQSPK_PK, crypto_kem_mlkem768_PUBLICKEYBYTES);
    prekey_bundle_asn1c.spk_identifier = to_UTF8String(prekey_bundle->MIST_SPK_IDENTIFIER);
    prekey_bundle_asn1c.pqspk_identifier = to_UTF8String(prekey_bundle->MIST_PQSPK_IDENTIFIER);
    prekey_bundle_asn1c.spk_signature = to_OCTET_STRING(prekey_bundle->MIST_SPK_SIGNATURE, MIST_XEDDSA_SIGNATURE_SIZE);
    prekey_bundle_asn1c.pqspk_signature = to_OCTET_STRING(prekey_bundle->MIST_PQSPK_SIGNATURE, MIST_XEDDSA_SIGNATURE_SIZE);

    contact.label = to_UTF8String(label);
    contact.memo = to_UTF8String(memo);
    contact.prekey_bundle = prekey_bundle_asn1c;

    asn_encode_to_new_buffer_result_t encoded = asn_encode_to_new_buffer(
        0,
        ATS_DER,
        &asn_DEF_Contact,
        &contact
    );
    if (encoded.result.encoded < 0)
        return serialization_error;

    *output = (unsigned char*) encoded.buffer;
    *output_size = (size_t) encoded.result.encoded; //The original value is a ssize_t.

    return success;
}
