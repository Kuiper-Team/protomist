#include "initialize.h"

#include <sodium.h>
#include <xeddsa.h>

#include "result.h"

result initialize_protomist() {
    if (sodium_init < 0)
        return libsodium_initialization_error;

    if (xeddsa_init() < 0)
        return libxeddsa_initialization_error;

    return success;
}
