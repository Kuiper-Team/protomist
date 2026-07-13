#include <assert.h>
#include <stdio.h>

#include "../source/constants.h"
#include "../source/identity.h"
#include "../source/wordlists/languages.h"

int main() {
    char* mnemonic_sentence[MIST_SEED_MNEMONIC_WORDS];
    MIST_GENERATE_MNEMONIC_SENTENCE(mnemonic_sentence, english_list);

    for (int index = 0; index < MIST_SEED_MNEMONIC_WORDS; index++) {
        char* word = mnemonic_sentence[index];
        assert(word != NULL);
        printf("%s ", word);
    }
}
