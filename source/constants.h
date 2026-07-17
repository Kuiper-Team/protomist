#ifndef constants_h
#define constants_h

#define MIST_SEED_SIZE 64 //512 bits
#define MIST_SEED_ENTROPY_SIZE 20 //160 bits
#define MIST_SEED_CHECKSUM_INPUT_SIZE (MIST_SEED_ENTROPY_SIZE / 4) //Entropy size divided by 32 bits
#define MIST_SEED_MNEMONIC_WORDS (MIST_SEED_ENTROPY_SIZE - MIST_SEED_CHECKSUM_INPUT_SIZE)
#define MIST_SEED_MNEMONIC_BITS_PER_WORD 11
#define MIST_SEED_MNEMONIC_SPACE " "
#define MIST_SEED_ITERATIONS 2048
#define MIST_BECH32M_HRP "mist"
#define MIST_BECH32M_HRP_SECRET "mistsecret"
#define MIST_BECH32M_HRP_SIGNATURE "mistsign"

#define seed_generation_hlen 64 //HMAC-SHA512
#define seed_generation_dklen_hlen_ratio (MIST_SEED_SIZE / seed_generation_hlen)
#define seed_generation_salt "mnemonic"
#define seed_generation_salt_size (sizeof(seed_generation_salt) - 1)
#define seed_generation_U1_concatenated_size (seed_generation_salt_size + 4) //32 bits = 4 bytes.
#define seed_generation_Un_concatenated_size (seed_generation_salt_size + seed_generation_hlen)
#define bip39_wordlist_size 2048

#define bech32m_encoding "bech32m"

#endif
