#include "messages.h"

#include "pqxdh.h"
#include "result.h"

result MIST_SERIALIZE_INITIAL_PAYLOAD( //Needs a better name. //WIP
    unsigned char* output,

    const struct initiator_prekey_bundle* MIST_PREKEY_BUNDLE,
    const unsigned char* MIST_CIPHERTEXT
) {
    //An initial ciphertext encrypted with some AEAD scheme using AD as associated data and using SK as the encryption key.

    return success;
}

//Notice: Protobuf or any serialization scheme to be adopted.
//To-do: Create a header file for the post-quantum Double Ratchet and use it in here.
