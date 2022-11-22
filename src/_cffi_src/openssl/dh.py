# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/dh.h>
"""

TYPES = """
typedef ... DH;

const long DH_NOT_SUITABLE_GENERATOR;
"""

FUNCTIONS = """
DH *DH_new(void);
void DH_free(DH *);
int DH_size(const DH *);
int DH_generate_key(DH *);
DH *DHparams_dup(DH *);

void DH_get0_pqg(const DH *, const BIGNUM **, const BIGNUM **,
                 const BIGNUM **);
int DH_set0_pqg(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
void DH_get0_key(const DH *, const BIGNUM **, const BIGNUM **);
int DH_set0_key(DH *, BIGNUM *, BIGNUM *);

int DH_check(const DH *, int *);
int DH_generate_parameters_ex(DH *, int, int, BN_GENCB *);
DH *d2i_DHparams_bio(BIO *, DH **);
int i2d_DHparams_bio(BIO *, DH *);
DH *d2i_DHxparams_bio(BIO *, DH **);
int i2d_DHxparams_bio(BIO *, DH *);

int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int pbits);
int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER && defined(OPENSSL_NO_DEPRECATED_3_0)
const long DH_NOT_SUITABLE_GENERATOR = 0;

DH *(*DH_new)(void) = NULL;
void (*DH_free)(DH *) = NULL;
int (*DH_size)(const DH *) = NULL;
int (*DH_generate_key)(DH *) = NULL;
DH *(*DHparams_dup)(DH *) = NULL;

void (*DH_get0_pqg)(const DH *, const BIGNUM **, const BIGNUM **,
                 const BIGNUM **) = NULL;
int (*DH_set0_pqg)(DH *, BIGNUM *, BIGNUM *, BIGNUM *) = NULL;
void (*DH_get0_key)(const DH *, const BIGNUM **, const BIGNUM **) = NULL;
int (*DH_set0_key)(DH *, BIGNUM *, BIGNUM *) = NULL;

int (*DH_check)(const DH *, int *) = NULL;
int (*DH_generate_parameters_ex)(DH *, int, int, BN_GENCB *) = NULL;
DH *(*d2i_DHparams_bio)(BIO *, DH **) = NULL;
int (*i2d_DHparams_bio)(BIO *, DH *) = NULL;
DH *(*d2i_DHxparams_bio)(BIO *, DH **) = NULL;
int (*i2d_DHxparams_bio)(BIO *, DH *) = NULL;
#else
#if !(defined(EVP_PKEY_DHX) && EVP_PKEY_DHX != -1)
DH *(*d2i_DHxparams_bio)(BIO *bp, DH **x) = NULL;
int (*i2d_DHxparams_bio)(BIO *bp, DH *x) = NULL;
#endif
#endif
"""
