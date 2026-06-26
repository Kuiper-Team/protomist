#include "helpers.h"

#include <sodium.h>
#include <stdbool.h>

bool check_libsodium() {
    if (sodium_init() < 0)
        return false;
    else
        return true;
}
