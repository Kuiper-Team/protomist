#ifndef result_h
#define result_h

typedef enum {
    success,

    libsodium_initialization_error,
    libxeddsa_initialization_error,
    out_of_memory,

    seed_hashing_error,
    seed_encryption_error,
    seed_decryption_error,

    invalid_wordlist,

    bech32_encoding_error,
    bech32_decoding_error,

    incorrect_signature,

    invalid_subkey_algorithm,

    malformed_contact_block,
    malformed_serialized_data,

    key_exchange_error,
    shared_secret_generation_error,

    serialization_error,
    deserialization_error
} result;

#endif
