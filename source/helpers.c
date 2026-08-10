#include "helpers.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "result.h"

result build_concatenated_buffer( //To-do: Don't allocate dynamically.
    unsigned char** destination,

    const unsigned char** blueprint,
    const size_t* sizes,
    const size_t count
) {
    size_t total_size = 0;
    for (size_t index = 0; index < count; index++)
        total_size += sizes[index];

    *destination = (unsigned char*) malloc(total_size);
    if (*destination == NULL)
        return out_of_memory;

    size_t jump = 0;
    for (size_t index = 0; index < count; index++) {
        const unsigned char* buffer = blueprint[index];
        const size_t size = sizes[index];

        memcpy(*destination + jump, buffer, size);
        jump += sizes[index];
    }

    return success;
}

void concatenate_bytes( //To-do: Don't allocate dynamically and return a result.
    unsigned char** destination,

    const size_t position,
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
