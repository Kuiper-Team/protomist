#include "wrapper.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

#include "../constants.h"
#include "../result.h"
#include "bech32.h"
#include "convert_bits.h"

result MIST_BECH32M_ENCODE(
    char** output, //Don't forget to free().

    const char* hrp,
    const unsigned char* MIST_DECODED,
    const size_t decoded_length
) {
    std::vector<uint8_t> data(MIST_DECODED, MIST_DECODED + decoded_length); //Converting array to vector

    size_t converted_decoded_size = (decoded_length * 8 + 4) / 5;
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
    std::string encoded(MIST_ENCODED);

    struct bech32::DecodeResult decoded = bech32::Decode(encoded, bech32::CharLimit::UNLIMITED);
    std::vector<uint8_t> data = decoded.data;

    size_t output_size = (data.size() * 5 + 7) / 8 + 1;
    size_t output_length = 0;
    *output = (unsigned char*) malloc(output_size * sizeof(uint8_t));
    if (*output == NULL)
        return out_of_memory;

    if (!convert_bits(
        *output,
        &output_length,
        8,
        data.data(),
        data.size(),
        5,
        0
    )) {
        free(*output);

        return bech32m_decoding_error;
    }

    if (output_length >= output_size) {
        free(*output);
        return bech32m_decoding_error;
    }
    (*output)[output_length] = '\0';

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
