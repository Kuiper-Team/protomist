#ifndef messages_h
#define messages_h

#include "pqxdh.h"
#include "result.h"

result MIST_SERIALIZE_INITIAL_PAYLOAD(
    unsigned char* output,

    const struct initiator_prekey_bundle* MIST_PREKEY_BUNDLE,
    const unsigned char* MIST_CIPHERTEXT
);

#endif
