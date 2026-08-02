#ifndef signal_h
#define signal_h

#include "result.h"

//A concatenate_bytes() helper is much needed.

result MIST_GENERATE_INITIATOR_PREKEY_BUNDLE(
    unsigned char* MIST_EK_output,

    const unsigned char* MIST_INITIATOR_IK
);

result MIST_GENERATE_RECIPIENT_PREKEY_BUNDLE(
    unsigned char* MIST_SPK_output,
    unsigned char* MIST_SPK_SIGNATURE_output,
    unsigned char* MIST_ZSPK_SIGNATURE_output,
    unsigned char* MIST_ZPQSPK_SIGNATURE_output,
    unsigned char* MIST_SPK_IDENTIFIER_output,

    const unsigned char* MIST_RECIPIENT_IK
);

result MIST_CALCULATE_SHARED_KEY(
    unsigned char* output,
    unsigned char* MIST_CIPHERTEXT_output,

    const unsigned char* MIST_INITIATOR_IK,
    const unsigned char* MIST_RECIPIENT_IK,
    const unsigned char* MIST_RECIPIENT_SPK,
    const unsigned char* MIST_RECIPIENT_EK,
    const unsigned char* MIST_SHARED_SECRET
);

result MIST_CALCULATE_ASSOCIATED_DATA(
    unsigned char* output,

    const unsigned char* MIST_INITIATOR_IK,
    const unsigned char* MIST_RECIPIENT_IK
);

result MIST_SERIALIZE_INITIAL_PAYLOAD(
    unsigned char* output,

    const unsigned char* MIST_IK,
    const unsigned char* MIST_EPK,
    const unsigned char* MIST_CIPHERTEXT
);

#endif
