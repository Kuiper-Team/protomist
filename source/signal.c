#include "signal.h"

result MIST_GENERATE_INITIATOR_PREKEY_BUNDLE( //WIP
    unsigned char* MIST_EK_output,

    const unsigned char* MIST_INITIATOR_IK
) {
    return success;
}

result MIST_GENERATE_RECIPIENT_PREKEY_BUNDLE( //WIP
    unsigned char* MIST_SPK_output,
    unsigned char* MIST_SPK_SIGNATURE_output,
    unsigned char* MIST_ZSPK_SIGNATURE_output,
    unsigned char* MIST_ZPQSPK_SIGNATURE_output,
    unsigned char* MIST_SPK_IDENTIFIER_output,

    const unsigned char* MIST_RECIPIENT_IK
) {
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
