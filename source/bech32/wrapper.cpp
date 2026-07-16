#include "wrapper.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include <iostream> //DEBUG

#include "../constants.h"
#include "../result.h"
#include "bech32.h"
#include "convert_bits.h"

result MIST_BECH32M_ENCODE(
    char** output, //Don't forget to free().

    const char* hrp,
    const unsigned char* MIST_DECODED,
    const size_t decoded_size
) {
    std::vector<uint8_t> data(MIST_DECODED, MIST_DECODED + decoded_size); //Converting array to vector

    size_t converted_decoded_size = (decoded_size * 8 + 4) / 5;
    uint8_t converted_array[converted_decoded_size];
    size_t converted_size = 0;
    if (!convert_bits(
        converted_array,
        &converted_size,
        5,
        data.data(),
        data.size(),
        8,
        1
    ))
        return bech32m_encoding_error;

    std::vector<uint8_t> converted(converted_array, converted_array + converted_size);

    std::string encoded_cpp = bech32::Encode(bech32::Encoding::BECH32M, hrp, converted);
    const char* encoded = encoded_cpp.c_str();

    *output = (char*) malloc(strlen(encoded) + 1);
    if (*output == NULL)
        return out_of_memory;

    strcpy(*output, encoded);

    return success;
}

result MIST_BECH32M_DECODE(
    unsigned char** output,

    const char* MIST_ENCODED
) {
    size_t encoded_size = strlen(MIST_ENCODED) + 1;
    std::string encoded(MIST_ENCODED, encoded_size);

    struct bech32::DecodeResult decoded = bech32::Decode(encoded, bech32::CharLimit::BECH32);
    if (decoded.encoding == bech32::Encoding::INVALID)
        return bech32m_decoding_error;

    std::vector<uint8_t> data = decoded.data;
    uint8_t* output_uint8_t;

    assert(!data.empty());

    const uint8_t* data_array = data.data();
    memcpy(output_uint8_t, data_array, data.size());

    size_t output_size = decoded.data.size();

    for (size_t index = 0; index < output_size; index++)
        (*output)[index] = (unsigned char) output_uint8_t[index];

    return success;
}

result MIST_BECH32M_VALIDATE(
    const char* MIST_ENCODED
) {
    size_t encoded_size = strlen(MIST_ENCODED) + 1;
    std::string encoded(MIST_ENCODED, encoded_size);

    auto errors = bech32::LocateErrors(encoded, bech32::CharLimit::BECH32);
    if (errors.first.empty())
        return success;
    else
        return bech32m_invalid;
}
