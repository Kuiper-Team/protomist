#ifndef convert_bits_h
#define convert_bits_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
);

#ifdef __cplusplus
}
#endif

#endif
