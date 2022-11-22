# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/dsa.h>
"""

TYPES = """
typedef ... DSA;
"""

FUNCTIONS = """
int DSA_generate_key(DSA *);
DSA *DSA_new(void);
void DSA_free(DSA *);
DSA *DSAparams_dup(DSA *);
int DSA_size(const DSA *);
int DSA_sign(int, const unsigned char *, int, unsigned char *, unsigned int *,
             DSA *);
int DSA_verify(int, const unsigned char *, int, const unsigned char *, int,
               DSA *);

void DSA_get0_pqg(const DSA *, const BIGNUM **, const BIGNUM **,
                  const BIGNUM **);
int DSA_set0_pqg(DSA *, BIGNUM *, BIGNUM *, BIGNUM *);
void DSA_get0_key(const DSA *, const BIGNUM **, const BIGNUM **);
int DSA_set0_key(DSA *, BIGNUM *, BIGNUM *);
int DSA_generate_parameters_ex(DSA *, int, unsigned char *, int,
                               int *, unsigned long *, BN_GENCB *);

int EVP_PKEY_CTX_set_dsa_paramgen_bits(EVP_PKEY_CTX *ctx, int nbits);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER && defined(OPENSSL_NO_DEPRECATED_3_0)
typedef void DSA;

int (*DSA_generate_key)(DSA *) = NULL;
DSA *(*DSA_new)(void) = NULL;
void (*DSA_free)(DSA *) = NULL;
DSA *(*DSAparams_dup)(DSA *) = NULL;
int (*DSA_size)(const DSA *) = NULL;
int (*DSA_sign)(int, const unsigned char *, int, unsigned char *, unsigned int *,
             DSA *) = NULL;
int (*DSA_verify)(int, const unsigned char *, int, const unsigned char *, int,
               DSA *) = NULL;

void (*DSA_get0_pqg)(const DSA *, const BIGNUM **, const BIGNUM **,
                  const BIGNUM **) = NULL;
int (*DSA_set0_pqg)(DSA *, BIGNUM *, BIGNUM *, BIGNUM *) = NULL;
void (*DSA_get0_key)(const DSA *, const BIGNUM **, const BIGNUM **) = NULL;
int (*DSA_set0_key)(DSA *, BIGNUM *, BIGNUM *) = NULL;
int (*DSA_generate_parameters_ex)(DSA *, int, unsigned char *, int,
                               int *, unsigned long *, BN_GENCB *) = NULL;
#endif
"""
