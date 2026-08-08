#ifndef pqxdh_h
#define pqxdh_h

#include <sodium.h>

#include "constants.h"
#include "result.h"

struct initiator_prekey_bundle {
    unsigned char MIST_IK_PK[crypto_sign_ed25519_PUBLICKEYBYTES];
    unsigned char MIST_EK_PK[crypto_box_PUBLICKEYBYTES];
};

struct initiator_prekey_secrets {
    unsigned char MIST_EK_SK[crypto_box_SECRETKEYBYTES];
};

struct recipient_prekey_bundle {
    unsigned char MIST_IK_PK[crypto_sign_ed25519_PUBLICKEYBYTES];

    unsigned char MIST_SPK_PK[crypto_box_PUBLICKEYBYTES];
    unsigned char MIST_PQSPK_PK[crypto_kem_mlkem768_PUBLICKEYBYTES];
    char* MIST_SPK_IDENTIFIER;
    char* MIST_PQSPK_IDENTIFIER;

    unsigned char MIST_SPK_SIGNATURE[crypto_sign_BYTES];
    unsigned char MIST_PQSPK_SIGNATURE[crypto_sign_BYTES];
};

struct recipient_prekey_secrets {
    unsigned char MIST_SPK_SK[crypto_box_SECRETKEYBYTES];
    unsigned char MIST_PQSPK_SK[crypto_kem_mlkem768_SECRETKEYBYTES];
};

result MIST_GENERATE_INITIATOR_PREKEY_BUNDLE(
    struct initiator_prekey_bundle* output,
    struct initiator_prekey_secrets* secrets_output,

    const unsigned char* MIST_INITIATOR_IK_PK
);

result MIST_GENERATE_RECIPIENT_PREKEY_BUNDLE(
    struct recipient_prekey_bundle* output,
    struct recipient_prekey_secrets* secrets_output,

    const unsigned char* MIST_RECIPIENT_IK_PK,
    const unsigned char* MIST_RECIPIENT_IK_SK,
    const size_t MIST_IDENTIFIER_NUMBER
);

result MIST_VERIFY_RECIPIENT_PREKEY_BUNDLE(
    const struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE
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
