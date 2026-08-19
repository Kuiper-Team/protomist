#include "ref10_plain.h"

#include <string.h>

static const unsigned char nonce[crypto_stream_salsa20_KEYBYTES] = {0};

int crypto_rng(
    unsigned char* r,
    unsigned char* n,
    const unsigned char* g
) {
    unsigned char x[crypto_stream_salsa20_KEYBYTES + RNG_OUTPUTBYTES];
    crypto_stream_salsa20(x, sizeof(x), nonce, g);
    memcpy(n, x, crypto_stream_salsa20_KEYBYTES);
    memcpy(r,x + crypto_stream_salsa20_KEYBYTES, RNG_OUTPUTBYTES);
    return 0;
}
