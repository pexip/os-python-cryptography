# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/hmac.h>
"""

TYPES = """
typedef ... HMAC_CTX;
"""

FUNCTIONS = """
int HMAC_Init_ex(HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *);
int HMAC_Update(HMAC_CTX *, const unsigned char *, size_t);
int HMAC_Final(HMAC_CTX *, unsigned char *, unsigned int *);
int HMAC_CTX_copy(HMAC_CTX *, HMAC_CTX *);

HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER && defined(OPENSSL_NO_DEPRECATED_3_0)
int (*HMAC_Init_ex)(HMAC_CTX *, const void *, int, const EVP_MD *, ENGINE *) = NULL;
int (*HMAC_Update)(HMAC_CTX *, const unsigned char *, size_t) = NULL;
int (*HMAC_Final)(HMAC_CTX *, unsigned char *, unsigned int *) = NULL;
int (*HMAC_CTX_copy)(HMAC_CTX *, HMAC_CTX *) = NULL;

HMAC_CTX *(*HMAC_CTX_new)(void) = NULL;
void (*HMAC_CTX_free)(HMAC_CTX *ctx) = NULL;
#endif
"""
