#include "identity.h"

#include <sodium.h>

#include "key.h"
#include "result.h"

result mist_identity_generate(
    mist_identity* output
) {
    mist_key_signing_generate(output);

    return success;
}
