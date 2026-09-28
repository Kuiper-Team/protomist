#include "wrapper.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../constants.h"
#include "../result.h"
#include "ref.h"

result mist_bech32m_encode(
    char** output, //Don't forget to free().
    size_t* output_size,

    const char* hrp,
    const unsigned char* input,
    const size_t input_length
) {
    size_t converted_input_size = (input_length * 8 + 4) / 5;
    uint8_t converted[converted_input_size];
    size_t converted_size = 0;
    if (!convert_bits(
        converted,
        &converted_size,
        5,
        (uint8_t*) input,
        input_length,
        8,
        1
    ))
        return bech32m_encoding_error;

    const size_t encoded_size = strlen(hrp) + 1 + input_length + MIST_BECH32_CS_LENGTH + 1;
    *output = malloc(encoded_size * sizeof(**output));
    if (*output == NULL)
        return out_of_memory;

    int encoding_result = bech32_encode(*output, hrp, converted, sizeof(converted), BECH32_ENCODING_BECH32M);
    if (encoding_result != 1)
        return bech32m_encoding_error;

    if (output_size != NULL)
        *output_size = encoded_size;

    return success;
}

result mist_bech32m_decode(
    unsigned char** output, //Don't forget to free().
    size_t* output_size,
    char** hrp_output,

    const char* input
) {
    const size_t encoded_length = strlen(input);
    if (encoded_length < MIST_BECH32_MIN_LENGTH || encoded_length > MIST_BECH32_MAX_LENGTH)
        return bech32m_decoding_error;

    const size_t decoded_max_size = encoded_length - MIST_BECH32_MIN_HRP_LENGTH - MIST_BECH32_SEPERATOR_LENGTH - MIST_BECH32_CS_LENGTH;
    uint8_t decoded[decoded_max_size];
    size_t decoded_size = 0;

    int decoding_result = bech32_decode(*hrp_output, decoded, &decoded_size, input);
    if (decoding_result == BECH32_ENCODING_NONE || decoded_size > decoded_max_size || decoding_result == BECH32_ENCODING_BECH32)
        return bech32m_decoding_error;

    const size_t converted_max_size = (decoded_size * 5 + 7) / 8;
    uint8_t converted[converted_max_size];

    size_t converted_size = 0;
    if (!convert_bits(
        converted,
        &converted_size,
        8,
        (uint8_t*) decoded,
        decoded_size,
        5,
        0
    ) || converted_size > converted_max_size)
        return bech32m_decoding_error;

    *output = malloc(converted_size * sizeof(uint8_t));
    if (*output == NULL)
        return out_of_memory;

    memcpy(*output, (unsigned char*) converted, converted_size);

    if (output_size != NULL)
        *output_size = converted_size;

    return success;
}
