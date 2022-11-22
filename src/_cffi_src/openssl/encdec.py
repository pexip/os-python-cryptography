# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#endif
"""

TYPES = """
typedef ... OSSL_DECODER_CTX;
typedef ... OSSL_ENCODER_CTX;
"""

FUNCTIONS = """
OSSL_DECODER_CTX *OSSL_DECODER_CTX_new_for_pkey(EVP_PKEY **,
                                                const char *, const char *,
                                                const char *, int,
                                                OSSL_LIB_CTX *, const char *);
void OSSL_DECODER_CTX_free(OSSL_DECODER_CTX *);
int OSSL_DECODER_from_bio(OSSL_DECODER_CTX *, BIO *);

OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new_for_pkey(const EVP_PKEY *, int,
                                                const char *, const char *,
                                                const char *);
void OSSL_ENCODER_CTX_free(OSSL_ENCODER_CTX *);
int OSSL_ENCODER_to_bio(OSSL_ENCODER_CTX *, BIO *);
int OSSL_ENCODER_CTX_set_cipher(OSSL_ENCODER_CTX *, const char *, const char *);
int OSSL_ENCODER_CTX_set_passphrase(OSSL_ENCODER_CTX *, const unsigned char *, size_t);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
#else
typedef void OSSL_DECODER_CTX;
typedef void OSSL_ENCODER_CTX;
OSSL_DECODER_CTX *(*OSSL_DECODER_CTX_new_for_pkey)(EVP_PKEY **,
                                                const char *, const char *,
                                                const char *, int,
                                                OSSL_LIB_CTX *, const char *) = NULL;
void (*OSSL_DECODER_CTX_free)(OSSL_DECODER_CTX *) = NULL;
int (*OSSL_DECODER_from_bio)(OSSL_DECODER_CTX *, BIO *) = NULL;

OSSL_ENCODER_CTX *(*OSSL_ENCODER_CTX_new_for_pkey)(const EVP_PKEY *, int,
                                                const char *, const char *,
                                                const char *) = NULL;
void (*OSSL_ENCODER_CTX_free)(OSSL_ENCODER_CTX *) = NULL;
int (*OSSL_ENCODER_to_bio)(OSSL_ENCODER_CTX *, BIO *) = NULL;
int (*OSSL_ENCODER_CTX_set_cipher)(OSSL_ENCODER_CTX *, const char *, const char *) = NULL;
int (*OSSL_ENCODER_CTX_set_passphrase)(OSSL_ENCODER_CTX *, const unsigned char *, size_t) = NULL;
#endif
"""
