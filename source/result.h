#ifndef result_h
#define result_h

typedef enum {
    success,

    libsodium_initialization_error,
    out_of_memory,

    seed_hashing_error,
    seed_encryption_error,
    seed_decryption_error,

    language_unavailable
} result;

#endif
