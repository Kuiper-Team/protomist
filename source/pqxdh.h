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
    unsigned char MIST_IK_SK[crypto_sign_ed25519_SECRETKEYBYTES];

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
    unsigned char MIST_IK_SK[crypto_sign_ed25519_SECRETKEYBYTES];

    unsigned char MIST_SPK_SK[crypto_box_SECRETKEYBYTES];
    unsigned char MIST_PQSPK_SK[crypto_kem_mlkem768_SECRETKEYBYTES];
};

result MIST_GENERATE_INITIATOR_PREKEY_BUNDLE(
    struct initiator_prekey_bundle* MIST_PREKEY_BUNDLE_output,
    struct initiator_prekey_secrets* MIST_PREKEY_SECRETS_output,

    const unsigned char* MIST_INITIATOR_IK_PK
);

result MIST_GENERATE_RECIPIENT_PREKEY_BUNDLE(
    struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE_output,
    struct recipient_prekey_secrets* MIST_PREKEY_SECRETS_output,

    const unsigned char* MIST_RECIPIENT_IK_PK,
    const unsigned char* MIST_RECIPIENT_IK_SK,
    const size_t MIST_IDENTIFIER_NUMBER
);

result MIST_VERIFY_RECIPIENT_PREKEY_BUNDLE(
    const struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE
);

result MIST_CALCULATE_CIPHERTEXT_AND_SHARED_KEY(
    unsigned char* MIST_CIPHERTEXT_output,
    unsigned char* MIST_SHARED_KEY_output,

    const struct initiator_prekey_bundle* MIST_INITIATOR_PREKEY_BUNDLE,
    const struct initiator_prekey_secrets* MIST_INITIATOR_PREKEY_SECRETS,
    const struct recipient_prekey_bundle* MIST_RECIPIENT_PREKEY_BUNDLE,
    const size_t MIST_IDENTIFIER_NUMBER
);

result MIST_CALCULATE_ASSOCIATED_DATA(
    unsigned char* output,

    const struct initiator_prekey_bundle* MIST_INITIATOR_PREKEY_BUNDLE,
    const struct recipient_prekey_bundle* MIST_RECIPIENT_PREKEY_BUNDLE
);

#endif
