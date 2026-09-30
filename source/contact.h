#ifndef contact_h
#define contact_h

#include "pqxdh.h"

struct mist_contact {
    char* label,
    char* memo,
    mist_pqxdh_recipient_prekey_bundle prekey_bundle,
}

#endif
