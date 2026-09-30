#ifndef key_h
#define key_h

#include "constants.h"
#include "result.h"

typedef struct {
    unsigned char public_key[MIST_ED25519_PK_SIZE];
    unsigned char secret_key[MIST_ED25519_SK_SIZE];
} mist_key_signing;

typedef struct {
    unsigned char public_key[MIST_X25519_PK_SIZE];
    unsigned char secret_key[MIST_X25519_SK_SIZE];
} mist_key_key_agreement;

typedef struct {
    unsigned char key[MIST_XCHACHA20_POLY1305_KEY_SIZE];
    unsigned char nonce[MIST_XCHACHA20_POLY1305_NONCE_SIZE];
} mist_key_encryption;

typedef struct {
    unsigned char public_key[MIST_MLKEM768_PK_SIZE];
    unsigned char secret_key[MIST_MLKEM768_SK_SIZE];
} mist_key_key_encapsulation;

result mist_key_signing_generate(
    mist_key_signing* output
);

result mist_key_key_agreement_generate(
    mist_key_key_agreement* output
);

result mist_key_encryption_generate(
    mist_key_encryption* output
);

result mist_key_key_encapsulation_generate(
    mist_key_key_encapsulation* output
);

result mist_key_signing_sign(
    unsigned char* output,

    const mist_key_signing signer,
    const unsigned char* input,
    const size_t input_size
);

result mist_key_signing_verify(
    const unsigned char* public_key,
    const unsigned char* signature,
    const size_t signature_size
);

result mist_key_key_agreement_sign(
    unsigned char* output,

    const mist_key_key_agreement signer,
    const unsigned char* input,
    const size_t input_size
); //Uses XEdDSA to sign.

result mist_key_key_agreement_dh(
    unsigned char* output,

    const unsigned char* local_secret_key,
    const unsigned char* remote_public_key
);

result mist_key_key_encapsulation_encapsulate(
    unsigned char* ciphertext_output,
    unsigned char* shared_secret_output,

    const mist_key_key_encapsulation key
);

result mist_key_key_encapsulation_decapsulate(
    unsigned char* ciphertext_output,
    unsigned char* shared_secret_output,

    const mist_key_key_encapsulation key
);

#endif
