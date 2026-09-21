#ifndef contact_h
#define contact_h

#include "pqxdh.h"

struct mist_contact {
    unsigned char* label,
    unsigned char* memo,
    struct recipient_prekey_bundle prekey_bundle,
}

#endif
