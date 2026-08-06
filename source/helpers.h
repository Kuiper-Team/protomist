#ifndef helpers_h
#define helpers_h

#include <math.h>
#include <stddef.h>

#define count_digits(number) (floor(log10(number)) + 1)

void concatenate_bytes(
    unsigned char** destination,

    const unsigned char* source1,
    const size_t source1_size,
    const unsigned char* source2,
    const size_t source1_size
);

#endif
