# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/evp.h>
"""

TYPES = """
typedef ... ASN1_PCTX;

typedef ... EVP_CIPHER;
typedef ... EVP_CIPHER_CTX;
typedef ... EVP_MD;
typedef ... EVP_MD_CTX;

typedef ... EVP_MAC;
typedef ... EVP_MAC_CTX;

typedef ... EVP_KEYMGMT;

typedef ... EVP_PKEY;
typedef ... EVP_PKEY_CTX;
static const int EVP_PKEY_NONE;
static const int EVP_PKEY_RSA;
static const int EVP_PKEY_RSA_PSS;
static const int EVP_PKEY_DSA;
static const int EVP_PKEY_DH;
static const int EVP_PKEY_DHX;
static const int EVP_PKEY_EC;
static const int EVP_PKEY_X25519;
static const int EVP_PKEY_ED25519;
static const int EVP_PKEY_X448;
static const int EVP_PKEY_ED448;
static const int EVP_PKEY_POLY1305;
static const int EVP_MAX_MD_SIZE;
static const int EVP_CTRL_AEAD_SET_IVLEN;
static const int EVP_CTRL_AEAD_GET_TAG;
static const int EVP_CTRL_AEAD_SET_TAG;
static const int EVP_PKEY_KEY_PARAMETERS;
static const int EVP_PKEY_PUBLIC_KEY;
static const int EVP_PKEY_KEYPAIR;

/* These come from core_dispatch.h, but that's included transitively */
static const int OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
static const int OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
static const int OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
static const int OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;

static const int Cryptography_HAS_EVP_PKEY_set_alias_type;
static const int Cryptography_HAS_SCRYPT;
static const int Cryptography_HAS_EVP_PKEY_DHX;
static const int Cryptography_HAS_EVP_PKEY_get_set_tls_encodedpoint;
static const long Cryptography_HAS_RAW_KEY;
static const long Cryptography_HAS_EVP_DIGESTFINAL_XOF;
static const long Cryptography_HAS_300_FIPS;
static const long Cryptography_HAS_300_EVP_CIPHER;
static const long Cryptography_HAS_EVP_PKEY_DH;
"""

FUNCTIONS = """
const EVP_CIPHER *EVP_get_cipherbyname(const char *);
EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *, const char *, const char *);
void EVP_CIPHER_free(EVP_CIPHER *);
const char *EVP_CIPHER_name(const EVP_CIPHER *);

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                      const unsigned char *, const unsigned char *, int);
int EVP_CipherUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                     const unsigned char *, int);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *, int);

int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *);
int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
int EVP_DigestUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *);
int EVP_DigestFinalXOF(EVP_MD_CTX *, unsigned char *, size_t);
const EVP_MD *EVP_get_digestbyname(const char *);
const char *EVP_MD_name(const EVP_MD *);

EVP_MAC *EVP_MAC_fetch(OSSL_LIB_CTX *, const char *, const char *);
void EVP_MAC_free(EVP_MAC *);

EVP_MAC_CTX *EVP_MAC_CTX_new(EVP_MAC *);
void EVP_MAC_CTX_free(EVP_MAC_CTX *);
EVP_MAC_CTX *EVP_MAC_CTX_dup(const EVP_MAC_CTX *);

int EVP_MAC_init(EVP_MAC_CTX *, const unsigned char *, size_t, const OSSL_PARAM[]);
int EVP_MAC_update(EVP_MAC_CTX *, const unsigned char *, size_t);
int EVP_MAC_final(EVP_MAC_CTX *, unsigned char *, size_t *, size_t);

EVP_KEYMGMT *EVP_KEYMGMT_fetch(OSSL_LIB_CTX *, const char *, const char *);
void EVP_KEYMGMT_free(EVP_KEYMGMT *);

EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *);
int EVP_PKEY_type(int);
int EVP_PKEY_size(EVP_PKEY *);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *);
DSA *EVP_PKEY_get1_DSA(EVP_PKEY *);
DH *EVP_PKEY_get1_DH(EVP_PKEY *);

int EVP_PKEY_encrypt(EVP_PKEY_CTX *, unsigned char *, size_t *,
                     const unsigned char *, size_t);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *, unsigned char *, size_t *,
                     const unsigned char *, size_t);

int EVP_SignInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_SignUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_SignFinal(EVP_MD_CTX *, unsigned char *, unsigned int *, EVP_PKEY *);

int EVP_VerifyInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_VerifyUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_VerifyFinal(EVP_MD_CTX *, const unsigned char *, unsigned int,
                    EVP_PKEY *);

int EVP_DigestSignInit(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *,
                       ENGINE *, EVP_PKEY *);
int EVP_DigestSignUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_DigestSignFinal(EVP_MD_CTX *, unsigned char *, size_t *);
int EVP_DigestVerifyInit(EVP_MD_CTX *, EVP_PKEY_CTX **, const EVP_MD *,
                         ENGINE *, EVP_PKEY *);



EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *, ENGINE *);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int, ENGINE *);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *);
int EVP_PKEY_sign_init(EVP_PKEY_CTX *);
int EVP_PKEY_sign(EVP_PKEY_CTX *, unsigned char *, size_t *,
                  const unsigned char *, size_t);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *);
int EVP_PKEY_verify(EVP_PKEY_CTX *, const unsigned char *, size_t,
                    const unsigned char *, size_t);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *, unsigned char *,
                            size_t *, const unsigned char *, size_t);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *);

int EVP_PKEY_set1_RSA(EVP_PKEY *, RSA *);
int EVP_PKEY_set1_DSA(EVP_PKEY *, DSA *);
int EVP_PKEY_set1_DH(EVP_PKEY *, DH *);

int EVP_PKEY_cmp(const EVP_PKEY *, const EVP_PKEY *);
int EVP_PKEY_eq(const EVP_PKEY *, const EVP_PKEY *);

int EVP_PKEY_check(EVP_PKEY_CTX *);
int EVP_PKEY_param_check(EVP_PKEY_CTX *);
int EVP_PKEY_public_check(EVP_PKEY_CTX *);

int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *);
int EVP_PKEY_paramgen(EVP_PKEY_CTX *, EVP_PKEY **);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *);
int EVP_PKEY_keygen(EVP_PKEY_CTX *, EVP_PKEY **);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *, EVP_PKEY *);
int EVP_PKEY_derive(EVP_PKEY_CTX *, unsigned char *, size_t *);
int EVP_PKEY_set_alias_type(EVP_PKEY *, int);
int EVP_PKEY_set_type(EVP_PKEY *, int);
int EVP_PKEY_set_type_by_keymgmt(EVP_PKEY *, EVP_KEYMGMT *);

EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *, const char *, const char *, ...);

int EVP_PKEY_copy_parameters(EVP_PKEY *, const EVP_PKEY *);

int EVP_PKEY_id(const EVP_PKEY *);
int EVP_PKEY_is_a(const EVP_PKEY *, const char *);

int EVP_PKEY_print_params(BIO *, const EVP_PKEY *, int, ASN1_PCTX *);
int EVP_PKEY_print_public(BIO *, const EVP_PKEY *, int, ASN1_PCTX *);
int EVP_PKEY_print_private(BIO *, const EVP_PKEY *, int, ASN1_PCTX *);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *);

int EVP_DigestSign(EVP_MD_CTX *, unsigned char *, size_t *,
                   const unsigned char *, size_t);
int EVP_DigestVerify(EVP_MD_CTX *, const unsigned char *, size_t,
                     const unsigned char *, size_t);
size_t EVP_PKEY_get1_tls_encodedpoint(EVP_PKEY *, unsigned char **);
int EVP_PKEY_set1_tls_encodedpoint(EVP_PKEY *, const unsigned char *,
                                   size_t);
size_t EVP_PKEY_get1_encoded_public_key(EVP_PKEY *, unsigned char **);
int EVP_PKEY_set1_encoded_public_key(EVP_PKEY *, const unsigned char *,
                                   size_t);

int EVP_PKEY_bits(const EVP_PKEY *);

int EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *);

EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *, EC_KEY *);

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *, int, int, void *);

int PKCS5_PBKDF2_HMAC(const char *, int, const unsigned char *, int, int,
                      const EVP_MD *, int, unsigned char *);

int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *, const EVP_MD *);

int EVP_PBE_scrypt(const char *, size_t, const unsigned char *, size_t,
                   uint64_t, uint64_t, uint64_t, uint64_t, unsigned char *,
                   size_t);

EVP_PKEY *EVP_PKEY_new_raw_private_key(int, ENGINE *, const unsigned char *,
                                       size_t);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int, ENGINE *, const unsigned char *,
                                      size_t);
int EVP_PKEY_get_raw_private_key(const EVP_PKEY *, unsigned char *, size_t *);
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *, unsigned char *, size_t *);

int EVP_PKEY_get_group_name(const EVP_PKEY *, char *, size_t, size_t *);

int EVP_PKEY_get_bn_param(const EVP_PKEY *, const char *, BIGNUM **);
int EVP_PKEY_get_int_param(const EVP_PKEY *, const char *, int *);
int EVP_PKEY_get_octet_string_param(const EVP_PKEY *, const char *,
                                    unsigned char *, size_t, size_t *);

int EVP_PKEY_set_bn_param(EVP_PKEY *, const char *, const BIGNUM *);
int EVP_PKEY_set_octet_string_param(EVP_PKEY *, const char *,
                                    const unsigned char *, size_t);
int EVP_PKEY_set_utf8_string_param(EVP_PKEY *, const char *, const char *);

int EVP_PKEY_todata(const EVP_PKEY *, int, OSSL_PARAM **);
int EVP_PKEY_fromdata_init(EVP_PKEY_CTX *);
int EVP_PKEY_fromdata(EVP_PKEY_CTX *, EVP_PKEY **, int, OSSL_PARAM[]);

int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *);
int EVP_default_properties_enable_fips(OSSL_LIB_CTX *, int);
"""

CUSTOMIZATIONS = """
#ifdef EVP_PKEY_DHX
const long Cryptography_HAS_EVP_PKEY_DHX = 1;
#else
const long Cryptography_HAS_EVP_PKEY_DHX = 0;
const long EVP_PKEY_DHX = -1;
#endif

EVP_MD_CTX *Cryptography_EVP_MD_CTX_new(void) {
    return EVP_MD_CTX_new();
}
void Cryptography_EVP_MD_CTX_free(EVP_MD_CTX *md) {
    EVP_MD_CTX_free(md);
}

#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_OPENSSL_300_OR_GREATER || \
        CRYPTOGRAPHY_IS_BORINGSSL
static const int Cryptography_HAS_EVP_PKEY_set_alias_type = 0;
int (*EVP_PKEY_set_alias_type)(EVP_PKEY *, int) = NULL;
#else
static const int Cryptography_HAS_EVP_PKEY_set_alias_type = 1;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL || defined(OPENSSL_NO_SCRYPT)
static const long Cryptography_HAS_SCRYPT = 0;
int (*EVP_PBE_scrypt)(const char *, size_t, const unsigned char *, size_t,
                      uint64_t, uint64_t, uint64_t, uint64_t, unsigned char *,
                      size_t) = NULL;
#else
static const long Cryptography_HAS_SCRYPT = 1;
#endif

#if !CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_EVP_PKEY_get_set_tls_encodedpoint = 1;
#else
static const long Cryptography_HAS_EVP_PKEY_get_set_tls_encodedpoint = 0;
size_t (*EVP_PKEY_get1_tls_encodedpoint)(EVP_PKEY *, unsigned char **) = NULL;
int (*EVP_PKEY_set1_tls_encodedpoint)(EVP_PKEY *, const unsigned char *,
                                      size_t) = NULL;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_EVP_DIGESTFINAL_XOF = 0;
int (*EVP_DigestFinalXOF)(EVP_MD_CTX *, unsigned char *, size_t) = NULL;
#if CRYPTOGRAPHY_LIBRESSL_LESS_THAN_370
static const long Cryptography_HAS_RAW_KEY = 0;
EVP_PKEY *(*EVP_PKEY_new_raw_private_key)(int, ENGINE *, const unsigned char *,
                                       size_t) = NULL;
EVP_PKEY *(*EVP_PKEY_new_raw_public_key)(int, ENGINE *, const unsigned char *,
                                      size_t) = NULL;
int (*EVP_PKEY_get_raw_private_key)(const EVP_PKEY *, unsigned char *,
                                    size_t *) = NULL;
int (*EVP_PKEY_get_raw_public_key)(const EVP_PKEY *, unsigned char *,
                                   size_t *) = NULL;
#else
static const long Cryptography_HAS_RAW_KEY = 1;
#endif
#else
static const long Cryptography_HAS_RAW_KEY = 1;
static const long Cryptography_HAS_EVP_DIGESTFINAL_XOF = 1;
#endif

/* This is tied to X25519 support so we reuse the Cryptography_HAS_X25519
   conditional to remove it. OpenSSL 1.1.0 didn't have this define, but
   1.1.1 will when it is released. We can remove this in the distant
   future when we drop 1.1.0 support. */
#ifndef EVP_PKEY_X25519
#define EVP_PKEY_X25519 NID_X25519
#endif

/* This is tied to X448 support so we reuse the Cryptography_HAS_X448
   conditional to remove it. OpenSSL 1.1.1 adds this define.  We can remove
   this in the distant future when we drop 1.1.0 support. */
#ifndef EVP_PKEY_X448
#define EVP_PKEY_X448 NID_X448
#endif

/* This is tied to ED25519 support so we reuse the Cryptography_HAS_ED25519
   conditional to remove it. */
#ifndef EVP_PKEY_ED25519
#define EVP_PKEY_ED25519 NID_ED25519
#endif

/* This is tied to ED448 support so we reuse the Cryptography_HAS_ED448
   conditional to remove it. */
#ifndef EVP_PKEY_ED448
#define EVP_PKEY_ED448 NID_ED448
#endif

/* This is tied to poly1305 support so we reuse the Cryptography_HAS_POLY1305
   conditional to remove it. */
#ifndef EVP_PKEY_POLY1305
#define EVP_PKEY_POLY1305 NID_poly1305
#endif

#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
static const long Cryptography_HAS_300_FIPS = 1;
static const long Cryptography_HAS_300_EVP_CIPHER = 1;

#ifdef OPENSSL_NO_DEPRECATED_3_0
int (*EVP_PKEY_assign_RSA)(EVP_PKEY *, RSA *) = NULL;
RSA *(*EVP_PKEY_get1_RSA)(EVP_PKEY *) = NULL;
DSA *(*EVP_PKEY_get1_DSA)(EVP_PKEY *) = NULL;
DH *(*EVP_PKEY_get1_DH)(EVP_PKEY *) = NULL;
EC_KEY *(*EVP_PKEY_get1_EC_KEY)(EVP_PKEY *) = NULL;
int (*EVP_PKEY_set1_RSA)(EVP_PKEY *, RSA *) = NULL;
int (*EVP_PKEY_set1_DSA)(EVP_PKEY *, DSA *) = NULL;
int (*EVP_PKEY_set1_DH)(EVP_PKEY *, DH *) = NULL;
int (*EVP_PKEY_set1_EC_KEY)(EVP_PKEY *, EC_KEY *) = NULL;
size_t (*EVP_PKEY_get1_tls_encodedpoint)(EVP_PKEY *, unsigned char **) = NULL;
int (*EVP_PKEY_set1_tls_encodedpoint)(EVP_PKEY *, const unsigned char *,
                                   size_t) = NULL;
int (*EVP_PKEY_cmp)(const EVP_PKEY *, const EVP_PKEY *) = NULL;
#endif

#else
typedef void EVP_KEYMGMT;
typedef void EVP_MAC;
typedef void EVP_MAC_CTX;
static const int EVP_PKEY_KEY_PARAMETERS = 0;
static const int EVP_PKEY_PUBLIC_KEY = 0;
static const int EVP_PKEY_KEYPAIR = 0;
static const int OSSL_KEYMGMT_SELECT_PRIVATE_KEY = 0;
static const int OSSL_KEYMGMT_SELECT_PUBLIC_KEY = 0;
static const int OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS = 0;
static const int OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS = 0;
static const long Cryptography_HAS_300_FIPS = 0;
static const long Cryptography_HAS_300_EVP_CIPHER = 0;
int (*EVP_default_properties_is_fips_enabled)(OSSL_LIB_CTX *) = NULL;
int (*EVP_default_properties_enable_fips)(OSSL_LIB_CTX *, int) = NULL;
EVP_CIPHER * (*EVP_CIPHER_fetch)(OSSL_LIB_CTX *, const char *,
                                 const char *) = NULL;
void (*EVP_CIPHER_free)(EVP_CIPHER *) = NULL;
EVP_MAC *(*EVP_MAC_fetch)(OSSL_LIB_CTX *, const char *, const char *) = NULL;
void (*EVP_MAC_free)(EVP_MAC *) = NULL;
EVP_MAC_CTX *(*EVP_MAC_CTX_new)(EVP_MAC *) = NULL;
void (*EVP_MAC_CTX_free)(EVP_MAC_CTX *) = NULL;
EVP_MAC_CTX *(*EVP_MAC_CTX_dup)(const EVP_MAC_CTX *) = NULL;
int (*EVP_MAC_init)(EVP_MAC_CTX *, const unsigned char *, size_t, const OSSL_PARAM[]) = NULL;
int (*EVP_MAC_update)(EVP_MAC_CTX *, const unsigned char *, size_t) = NULL;
int (*EVP_MAC_final)(EVP_MAC_CTX *, unsigned char *, size_t *, size_t) = NULL;

EVP_KEYMGMT *(*EVP_KEYMGMT_fetch)(OSSL_LIB_CTX *, const char *, const char *) = NULL;
void (*EVP_KEYMGMT_free)(EVP_KEYMGMT *) = NULL;
int (*EVP_PKEY_is_a)(const EVP_PKEY *, const char *) = NULL;
int (*EVP_PKEY_get_group_name)(const EVP_PKEY *, char *, size_t, size_t *) = NULL;
int (*EVP_PKEY_set_type_by_keymgmt)(EVP_PKEY *, EVP_KEYMGMT *) = NULL;
EVP_PKEY *(*EVP_PKEY_Q_keygen)(OSSL_LIB_CTX *, const char *, const char *, ...) = NULL;
int (*EVP_PKEY_get_bn_param)(const EVP_PKEY *, const char *, BIGNUM **) = NULL;
int (*EVP_PKEY_get_int_param)(const EVP_PKEY *, const char *, int *) = NULL;
int (*EVP_PKEY_get_octet_string_param)(const EVP_PKEY *, const char *,
                                    unsigned char *, size_t, size_t *) = NULL;
int (*EVP_PKEY_set_bn_param)(EVP_PKEY *, const char *, const BIGNUM *) = NULL;
int (*EVP_PKEY_set_octet_string_param)(EVP_PKEY *, const char *,
                                    const unsigned char *, size_t) = NULL;
int (*EVP_PKEY_set_utf8_string_param)(EVP_PKEY *, const char *, const char *) = NULL;
int (*EVP_PKEY_todata)(const EVP_PKEY *, int, OSSL_PARAM **) = NULL;
int (*EVP_PKEY_fromdata_init)(EVP_PKEY_CTX *) = NULL;
int (*EVP_PKEY_fromdata)(EVP_PKEY_CTX *, EVP_PKEY **, int, OSSL_PARAM[]) = NULL;
size_t (*EVP_PKEY_get1_encoded_public_key)(EVP_PKEY *, unsigned char **) = EVP_PKEY_get1_tls_encodedpoint;
int (*EVP_PKEY_set1_encoded_public_key)(EVP_PKEY *, const unsigned char *,
                                   size_t) = EVP_PKEY_set1_tls_encodedpoint;
int (*EVP_PKEY_eq)(const EVP_PKEY *, const EVP_PKEY *) = EVP_PKEY_cmp;
#endif

#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_EVP_PKEY_DH = 0;
int (*EVP_PKEY_set1_DH)(EVP_PKEY *, DH *) = NULL;
#else
static const long Cryptography_HAS_EVP_PKEY_DH = 1;
#endif
"""
