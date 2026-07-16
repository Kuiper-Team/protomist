#include "convert_bits.h"

#include <stddef.h>
#include <stdint.h>

//Attribution: https://github.com/BlockchainCommons/bc-bech32
//Copyright (c) 2017 Pieter Wuille
int convert_bits(
    uint8_t* out,
    size_t* outlen,
    int outbits,
    const uint8_t* in,
    size_t inlen,
    int inbits,
    int pad
) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;

}
