#ifndef serialization_decoder_h
#define serialization_decoder_h

#include <stddef.h>

#include "../contact.h"
#include "../pqxdh.h"
#include "../result.h"

result mist_serialization_contact_deserialize(
    mist_contact* output,

    const unsigned char* input,
    const size_t input_size
);

#endif
