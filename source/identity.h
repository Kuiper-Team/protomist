#ifndef identity_h
#define identity_h

#include "constants.h"
#include "key.h"
#include "result.h"

typedef mist_key_signing mist_identity;

result mist_identity_generate(
    mist_identity* output
);

#endif
