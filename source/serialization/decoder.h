#ifndef serialization_decoder_h
#define serialization_decoder_h

#include <stddef.h>
#include <stdint.h>

#include "../pqxdh.h"
#include "../result.h"

result MIST_DESERIALIZE_CONTACT(
    char** MIST_LABEL_output,
    char** MIST_MEMO_output,
    recipient_prekey_bundle* MIST_PREKEY_BUNDLE_output,

    const unsigned char* MIST_ENCODED,
    const size_t MIST_ENCODED_size
);

#endif
