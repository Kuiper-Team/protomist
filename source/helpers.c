#include "helpers.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "result.h"

void concatenate_bytes(
    unsigned char* destination,

    const size_t position,
    const unsigned char* source1,
    const size_t source1_size,
    const unsigned char* source2,
    const size_t source2_size
) {
    memcpy(destination, source1, source1_size);
    memcpy(destination + source1_size, source2, source2_size); //Pointer arithmetic
}

result build_concatenated_buffer(
    unsigned char* destination,

    const unsigned char** blueprint,
    const size_t* sizes,
    const size_t count
) {
    size_t jump = 0;
    for (size_t index = 0; index < count; index++) {
        const unsigned char* buffer = blueprint[index];
        const size_t size = sizes[index];

        memcpy(destination + jump, buffer, size);
        jump += sizes[index];
    }

    return success;
}
