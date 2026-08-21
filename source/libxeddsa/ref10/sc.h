#ifndef libxeddsa_ref10_sc_h
#define libxeddsa_ref10_sc_h

void sc_muladd(unsigned char* s, const unsigned char* a, const unsigned char* b, const unsigned char* c);
void sc_reduce(unsigned char* s);

#endif
