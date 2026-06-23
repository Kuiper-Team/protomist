#ifndef result_h
#define result_h

typedef enum {
    success,

    libsodium_initialization_error,
    out_of_memory,

    seed_decryption_error
} result;

#endif
