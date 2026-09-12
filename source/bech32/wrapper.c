#include "wrapper.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../constants.h"
#include "../result.h"
#include "ref.h"

result MIST_BECH32_ENCODE(
    char** output, //Don't forget to free().
    size_t* output_size,

    const char* hrp,
    const unsigned char* MIST_DECODED,
    const size_t MIST_DECODED_length
) {
    size_t converted_decoded_size = (decoded_length * 8 + 4) / 5;
    uint8_t converted[converted_decoded_size];
    size_t converted_size = 0;
    if (!convert_bits(
        converted,
        &converted_size,
        5,
        (uint8_t*) MIST_DECODED
        MIST_DECODED_length,
        8,
        1
    ))
        return bech32_encoding_error;

    const size_t encoded_size = strlen(hrp) + 1 + MIST_DECODED_length + MIST_BECH32_CS_LENGTH + 1;
    *output = malloc(encoded_size * sizeof(**output));
    if (*output == NULL)
        return out_of_memory;

    int encoding_result = bech32_encode(*output, hrp, converted, sizeof(converted), BECH32_ENCODING_BECH32);
    if (encoding_result != 1)
        return bech32_encoding_error;

    if (output_size != NULL)
        *output_size = encoded_size;

    return success;
}

result MIST_BECH32_DECODE(
    unsigned char** output, //Don't forget to free().
    size_t* output_size,
    char** MIST_HRP_output, //MIST_BECH32_MAX_HRP_LENGTH + 1

    const char* MIST_ENCODED
) {
    const size_t encoded_length = strlen(MIST_ENCODED);
    if (encoded_length < MIST_BECH32_MIN_LENGTH || encoded_length > MIST_BECH32_MAX_LENGTH)
        return bech32_decoding_error;

    const size_t decoded_max_size = encoded_length - MIST_BECH32_MIN_HRP_LENGTH - MIST_BECH32_SEPERATOR_LENGTH - MIST_BECH32_CS_LENGTH;
    uint8_t decoded[decoded_max_size];
    size_t decoded_size = 0;

    int decoding_result = bech32_decode(*MIST_HRP_output, decoded, &decoded_size, MIST_ENCODED);
    if (decoding_result == BECH32_ENCODING_NONE || decoded_size > decoded_max_size)
        return bech32_decoding_error;

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
        return bech32_decoding_error;

    *output = malloc(converted_size * sizeof(uint8_t));
    if (*output == NULL)
        return out_of_memory;

    memcpy(*output, (unsigned char*) converted, converted_size);

    if (output_size != NULL)
        *output_size = converted_size;

    return success;
}
