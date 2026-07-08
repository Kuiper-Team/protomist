#ifndef dependencies_bech32_wrapper_h
#define dependencies_bech32_wrapper_h

#include "../result.h"

#ifdef __cplusplus
extern "C" {
#endif

result MIST_BECH32M_ENCODE(
    unsigned char* output
);
result MIST_BECH32M_DECODE(
    unsigned char* output
);

#ifdef __cplusplus
}
#endif

#endif
