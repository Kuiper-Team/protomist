#ifndef xeddsa_additions_h
#define xeddsa_additions_h

#define MAX_MSG_LEN 256 //???

#include "types.h"

//fe
typedef crypto_int32 fe[10];

//ge
typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;

//crypto_additions
void sc_neg(unsigned char *b, const unsigned char *a);
void sc_cmov(unsigned char* f, const unsigned char* g, unsigned char b);

int fe_isequal(const fe f, const fe g);
int fe_isreduced(const unsigned char* s);
void fe_mont_rhs(fe v2, const fe u);
void fe_montx_to_edy(fe y, const fe u);
void fe_sqrt(fe b, const fe a);

int ge_isneutral(const ge_p3* q);
void ge_neg(ge_p3* r, const ge_p3 *p);
void ge_montx_to_p3(ge_p3* p, const fe u, const unsigned char ed_sign_bit);
void ge_p3_to_montx(fe u, const ge_p3 *p);
void ge_scalarmult(ge_p3 *h, const unsigned char *a, const ge_p3 *A);
void ge_scalarmult_cofactor(ge_p3 *q, const ge_p3 *p);

void elligator(fe u, const fe r);
void hash_to_point(ge_p3* p, const unsigned char* msg, const unsigned long in_len);

int crypto_sign_modified(
    unsigned char* sm,

    const unsigned char* m,
    unsigned long long mlen,
    const unsigned char* sk,
    const unsigned char* pk,
    const unsigned char* random,
);

int crypto_sign_open_modified(
    unsigned char* m,

    const unsigned char* sm,
    unsigned long long smlen,
    const unsigned char* pk
);

#endif
