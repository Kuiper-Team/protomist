#include "wrapper.h"

#include <string.h>

#include "bech32.h"
#include "../constants.h"
#include "../result.h"

result MIST_BECH32M_ENCODE(
    unsigned char** output,

    const unsigned char* MIST_DECODED,
    const size_t decoded_size
) {
    std::vector<uint8_t> data(MIST_DECODED, MIST_DECODED + decoded_size); //Converting array to vector

    std::string encoded_cpp = Encode(Encoding::BECH32M, bech32m_hrp_1, data);
    const char* encoded = encoded_cpp.c_str();
    strcpy(*output, encoded);

    return success;
}

result MIST_BECH32M_DECODE(
    unsigned char** output,

    const unsigned char* MIST_ENCODED
) {
    struct DecodeResult decoded = Decode(MIST_ENCODED, CharLimit::BECH32);
    if (decoded.empty())
        return bech32m_decoding_error;

    uint8_t* output_uint8_t;
    memcpy(output_uint8_t, &decoded.data[0]);

    size_t output_size = decoded.data.size();

    for (int index = 0; index < output_size; index++)
        (*output)[index] = (unsigned char) output_uint8_t[index];

    return success;
}

result MIST_BECH32M_VALIDATE(
    const char* MIST_ENCODED
) {
    std::string encoded = str(MIST_ENCODED);

    auto errors = LocateErrors(encoded, CharLimit::BECH32);
    if (errors.first.empty())
        return success;
    else
        return bech32m_invalid;
}
