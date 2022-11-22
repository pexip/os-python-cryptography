# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
#include <openssl/core.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#endif
"""

TYPES = """
typedef ... OSSL_PARAM;
typedef ... OSSL_PARAM_BLD;
"""

FUNCTIONS = """
OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
void OSSL_PARAM_BLD_free(OSSL_PARAM_BLD *);

int OSSL_PARAM_BLD_push_BN(OSSL_PARAM_BLD *, const char *, const BIGNUM *);
int OSSL_PARAM_BLD_push_utf8_string(OSSL_PARAM_BLD *, const char *, const char *, size_t);
int OSSL_PARAM_BLD_push_octet_string(OSSL_PARAM_BLD *, const char *, const void *, size_t);

OSSL_PARAM *OSSL_PARAM_BLD_to_param(OSSL_PARAM_BLD *);

void OSSL_PARAM_free(OSSL_PARAM *);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
#else
typedef void OSSL_PARAM;
typedef void OSSL_PARAM_BLD;
OSSL_PARAM_BLD *(*OSSL_PARAM_BLD_new)(void) = NULL;
void (*OSSL_PARAM_BLD_free)(OSSL_PARAM_BLD *) = NULL;

int (*OSSL_PARAM_BLD_push_BN)(OSSL_PARAM_BLD *, const char *, const BIGNUM *) = NULL;
int (*OSSL_PARAM_BLD_push_utf8_string)(OSSL_PARAM_BLD *, const char *, const char *, size_t) = NULL;
int (*OSSL_PARAM_BLD_push_octet_string)(OSSL_PARAM_BLD *, const char *, const void *, size_t) = NULL;

OSSL_PARAM *(*OSSL_PARAM_BLD_to_param)(OSSL_PARAM_BLD *) = NULL;

void (*OSSL_PARAM_free)(OSSL_PARAM *) = NULL;
#endif
"""
