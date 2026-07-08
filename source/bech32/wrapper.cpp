#include "wrapper.h"

#include <string.h>

#include "bech32.h"
#include "../constants.h"
#include "../result.h"

result MIST_BECH32M_ENCODE(
    unsigned char* output
) {
    const std::vector<uint8_t> data; //How?
    Encode(bech32m_encoding, bech32m_hrp_1, data); //Error handling?

    return success;
}

result MIST_BECH32M_DECODE(
    unsigned char* output
) {
    return success;
}
