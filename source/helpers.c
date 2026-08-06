#include "helpers.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void concatenate_bytes(
    unsigned char** destination,

    const unsigned char* source1,
    const size_t source1_size,
    const unsigned char* source2,
    const size_t source2_size
) { //Don't forget to free() destination!
    const size_t buffer_size = source1_size + source2_size;
    *destination = (unsigned char*) malloc(buffer_size);

    memcpy(*destination, source1, source1_size);
    memcpy(*destination + source1_size, source2, source2_size); //Pointer arithmetic
}
