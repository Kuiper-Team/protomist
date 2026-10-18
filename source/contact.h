#ifndef contact_h
#define contact_h

#include "pqxdh.h"

typedef struct {
    char* label;
    char* memo;
    mist_pqxdh_recipient_prekeys prekey_bundle;
} mist_contact;

#endif
