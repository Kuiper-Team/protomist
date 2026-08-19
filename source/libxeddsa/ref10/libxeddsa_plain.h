#ifndef libxeddsa_ref10_plain_h
#define libxeddsa_ref10_plain_h

#define CRYPTO_OUTPUTBYTES 64
#define CRYPTO_INPUTBYTES 16
#define CRYPTO_KEYBYTES 32
#define CRYPTO_CONSTBYTES 16
#define RNG_OUTPUTBYTES 736
#define ROUNDS 20

//core.c
static uint32 rotate(
    uint32 u,
    int c
);
static uint32 load_littleendian(
    const unsigned char* x
);
static void store_littleendian(
    unsigned char* x,
    uint32 u
);
int crypto_core(
    unsigned char* out,
    const unsigned char* in,
    const unsigned char* k,
    const unsigned char* c
);

//rng.c
int crypto_rng(
    unsigned char* r, /* random output */
    unsigned char* n, /* new key */
    const unsigned char* g  /* old key */
);

#endif
