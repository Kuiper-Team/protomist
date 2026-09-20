#include "initialize.h"

#include <sodium.h>

#include "result.h"

result mist_initialize() {
    if (sodium_init() == -1)
        return libsodium_initialization_error;

    return success;
}
