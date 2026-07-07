#include <assert.h>
#include <stdio.h>

#include "../source/constants.h"
#include "../source/identity.h"
#include "../source/types.h"

int main() {
    unsigned char output[MIST_SEED_MNEMONIC_WORDS];
    MIST_GENERATE_MNEMONIC_SENTENCE(output, en);
}
