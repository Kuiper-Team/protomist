#ifndef constants_h
#define constants_h

#define MIST_SEED_SIZE 64
#define MIST_SEED_ENTROPY_SIZE 20 //160 bits
#define MIST_SEED_MNEMONIC_WORDS ((MIST_SEED_ENTROPY_SIZE * 8 + MIST_SEED_ENTROPY_SIZE * 8 / 3) / 11)
#define MIST_SEED_ITERATIONS 2048

#define seed_generation_salt "mnemonic"

#endif
