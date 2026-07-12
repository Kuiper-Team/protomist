#include <assert.h>
#include <stdio.h>

#include "../source/constants.h"
#include "../source/identity.h"
#include "../source/wordlists/languages.h"

int main() {
    char mnemonic_sentence[MIST_SEED_MNEMONIC_WORDS];
    char* mnemonic_sentence_pointer = mnemonic_sentence;
    MIST_GENERATE_MNEMONIC_SENTENCE(&mnemonic_sentence_pointer, english_list);

    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++)
        assert(mnemonic_sentence[index] != NULL);
}
