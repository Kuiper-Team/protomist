#ifndef serialization_encoder_h
#define serialization_encoder_h

#include <stddef.h>

#include "../pqxdh.h"
#include "../result.h"

result MIST_SERIALIZE_CONTACT(
    unsigned char** output,
    size_t* output_size,

    const char* MIST_LABEL,
    const char* MIST_MEMO,
    const struct recipient_prekey_bundle* MIST_PREKEY_BUNDLE
);

#endif
