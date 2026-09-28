#ifndef pqxdh_h
#define pqxdh_h

#include <sodium.h>

#include "constants.h"
#include "identity.h"
#include "result.h"
#include "subkey.h"

typedef struct {
    mist_identity identity;

    mist_subkey_key_agreement ek;
} mist_pqxdh_initiator_prekeys;

typedef struct {
    mist_identity identity;

    mist_subkey_key_agreement spk;
    mist_subkey_key_encapsulation pqspk;

    unsigned char spk_signature[MIST_XEDDSA_SIGNATURE_SIZE];
    unsigned char pqspk_signature[MIST_XEDDSA_SIGNATURE_SIZE];
} mist_pqxdh_recipient_prekeys;

result mist_pqxdh_initiator_prekeys_ek_rotate(
    mist_pqxdh_initiator_prekeys* initiator_prekeys,

    const uint32_t identifier
);

result mist_pqxdh_recipient_prekeys_spk_rotate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const uint32_t identifier
);

result mist_pqxdh_recipient_prekeys_pqspk_rotate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const uint32_t identifier
);

result mist_pqxdh_initiator_prekeys_generate(
    mist_pqxdh_initiator_prekeys* initiator_prekeys,

    const mist_identity identity,
    const uint32_t ek_identifier
);

result mist_pqxdh_recipient_prekeys_generate(
    mist_pqxdh_recipient_prekeys* recipient_prekeys,

    const mist_identity identity,
    const uint32_t spk_identifier,
    const uint32_t pqspk_identifier
);

result mist_pqxdh_recipient_prekeys_verify(
    const mist_pqxdh_recipient_prekeys recipient_prekeys
);

result mist_pqxdh_shared_key(
    unsigned char* ciphertext_output,
    unsigned char* shared_key_output,

    const mist_pqxdh_initiator_prekeys initiator_prekeys,
    const mist_pqxdh_recipient_prekeys recipient_prekeys,
    const uint32_t identifier
);

result mist_pqxdh_associated_data(
    unsigned char* output,

    const mist_pqxdh_initiator_prekeys initiator_prekeys,
    const mist_pqxdh_recipient_prekeys recipient_prekeys
);

#endif
