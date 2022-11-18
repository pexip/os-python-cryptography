# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import threading
import typing

from cryptography.exceptions import (
    InvalidSignature,
    UnsupportedAlgorithm,
    _Reasons,
)
from cryptography.hazmat.backends.openssl.utils import (
    _calculate_digest_and_algorithm,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.asymmetric.padding import (
    MGF1,
    OAEP,
    PSS,
    AsymmetricPadding,
    PKCS1v15,
    _Auto,
    _DigestLength,
    _MaxLength,
    calculate_max_pss_salt_length,
)
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPrivateNumbers,
    RSAPublicKey,
    RSAPublicNumbers,
)

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.backend import Backend


def _get_rsa_pss_salt_length(
    backend: "Backend",
    pss: PSS,
    key: typing.Union[RSAPrivateKey, RSAPublicKey],
    hash_algorithm: hashes.HashAlgorithm,
) -> int:
    salt = pss._salt_length

    if isinstance(salt, _MaxLength):
        return calculate_max_pss_salt_length(key, hash_algorithm)
    elif isinstance(salt, _DigestLength):
        return hash_algorithm.digest_size
    elif isinstance(salt, _Auto):
        if isinstance(key, RSAPrivateKey):
            raise ValueError(
                "PSS salt length can only be set to AUTO when verifying"
            )
        return backend._lib.RSA_PSS_SALTLEN_AUTO
    else:
        return salt


def _enc_dec_rsa(
    backend: "Backend",
    key: typing.Union["_RSAPrivateKey", "_RSAPublicKey"],
    data: bytes,
    padding: AsymmetricPadding,
) -> bytes:
    if not isinstance(padding, AsymmetricPadding):
        raise TypeError("Padding must be an instance of AsymmetricPadding.")

    if isinstance(padding, PKCS1v15):
        padding_enum = backend._lib.RSA_PKCS1_PADDING
    elif isinstance(padding, OAEP):
        padding_enum = backend._lib.RSA_PKCS1_OAEP_PADDING

        if not isinstance(padding._mgf, MGF1):
            raise UnsupportedAlgorithm(
                "Only MGF1 is supported by this backend.",
                _Reasons.UNSUPPORTED_MGF,
            )

        if not backend.rsa_padding_supported(padding):
            raise UnsupportedAlgorithm(
                "This combination of padding and hash algorithm is not "
                "supported by this backend.",
                _Reasons.UNSUPPORTED_PADDING,
            )

    else:
        raise UnsupportedAlgorithm(
            "{} is not supported by this backend.".format(padding.name),
            _Reasons.UNSUPPORTED_PADDING,
        )

    return _enc_dec_rsa_pkey_ctx(backend, key, data, padding_enum, padding)


def _enc_dec_rsa_pkey_ctx(
    backend: "Backend",
    key: typing.Union["_RSAPrivateKey", "_RSAPublicKey"],
    data: bytes,
    padding_enum: int,
    padding: AsymmetricPadding,
) -> bytes:
    init: typing.Callable[[typing.Any], int]
    crypt: typing.Callable[[typing.Any, typing.Any, int, bytes, int], int]
    if isinstance(key, _RSAPublicKey):
        init = backend._lib.EVP_PKEY_encrypt_init
        crypt = backend._lib.EVP_PKEY_encrypt
    else:
        init = backend._lib.EVP_PKEY_decrypt_init
        crypt = backend._lib.EVP_PKEY_decrypt

    pkey_ctx = backend._lib.EVP_PKEY_CTX_new(key._evp_pkey, backend._ffi.NULL)
    backend.openssl_assert(pkey_ctx != backend._ffi.NULL)
    pkey_ctx = backend._ffi.gc(pkey_ctx, backend._lib.EVP_PKEY_CTX_free)
    res = init(pkey_ctx)
    backend.openssl_assert(res == 1)
    res = backend._lib.EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_enum)
    backend.openssl_assert(res > 0)
    buf_size = backend._lib.EVP_PKEY_size(key._evp_pkey)
    backend.openssl_assert(buf_size > 0)
    if isinstance(padding, OAEP):
        mgf1_md = backend._evp_md_non_null_from_algorithm(
            padding._mgf._algorithm
        )
        res = backend._lib.EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, mgf1_md)
        backend.openssl_assert(res > 0)
        oaep_md = backend._evp_md_non_null_from_algorithm(padding._algorithm)
        res = backend._lib.EVP_PKEY_CTX_set_rsa_oaep_md(pkey_ctx, oaep_md)
        backend.openssl_assert(res > 0)

    if (
        isinstance(padding, OAEP)
        and padding._label is not None
        and len(padding._label) > 0
    ):
        # set0_rsa_oaep_label takes ownership of the char * so we need to
        # copy it into some new memory
        labelptr = backend._lib.OPENSSL_malloc(len(padding._label))
        backend.openssl_assert(labelptr != backend._ffi.NULL)
        backend._ffi.memmove(labelptr, padding._label, len(padding._label))
        res = backend._lib.EVP_PKEY_CTX_set0_rsa_oaep_label(
            pkey_ctx, labelptr, len(padding._label)
        )
        backend.openssl_assert(res == 1)

    outlen = backend._ffi.new("size_t *", buf_size)
    buf = backend._ffi.new("unsigned char[]", buf_size)
    # Everything from this line onwards is written with the goal of being as
    # constant-time as is practical given the constraints of Python and our
    # API. See Bleichenbacher's '98 attack on RSA, and its many many variants.
    # As such, you should not attempt to change this (particularly to "clean it
    # up") without understanding why it was written this way (see
    # Chesterton's Fence), and without measuring to verify you have not
    # introduced observable time differences.
    res = crypt(pkey_ctx, buf, outlen, data, len(data))
    resbuf = backend._ffi.buffer(buf)[: outlen[0]]
    backend._lib.ERR_clear_error()
    if res <= 0:
        raise ValueError("Encryption/decryption failed.")
    return resbuf


def _rsa_sig_determine_padding(
    backend: "Backend",
    key: typing.Union["_RSAPrivateKey", "_RSAPublicKey"],
    padding: AsymmetricPadding,
    algorithm: typing.Optional[hashes.HashAlgorithm],
) -> int:
    if not isinstance(padding, AsymmetricPadding):
        raise TypeError("Expected provider of AsymmetricPadding.")

    pkey_size = backend._lib.EVP_PKEY_size(key._evp_pkey)
    backend.openssl_assert(pkey_size > 0)

    if isinstance(padding, PKCS1v15):
        # Hash algorithm is ignored for PKCS1v15-padding, may be None.
        padding_enum = backend._lib.RSA_PKCS1_PADDING
    elif isinstance(padding, PSS):
        if not isinstance(padding._mgf, MGF1):
            raise UnsupportedAlgorithm(
                "Only MGF1 is supported by this backend.",
                _Reasons.UNSUPPORTED_MGF,
            )

        # PSS padding requires a hash algorithm
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError("Expected instance of hashes.HashAlgorithm.")

        # Size of key in bytes - 2 is the maximum
        # PSS signature length (salt length is checked later)
        if pkey_size - algorithm.digest_size - 2 < 0:
            raise ValueError(
                "Digest too large for key size. Use a larger "
                "key or different digest."
            )

        padding_enum = backend._lib.RSA_PKCS1_PSS_PADDING
    else:
        raise UnsupportedAlgorithm(
            "{} is not supported by this backend.".format(padding.name),
            _Reasons.UNSUPPORTED_PADDING,
        )

    return padding_enum


# Hash algorithm can be absent (None) to initialize the context without setting
# any message digest algorithm. This is currently only valid for the PKCS1v15
# padding type, where it means that the signature data is encoded/decoded
# as provided, without being wrapped in a DigestInfo structure.
def _rsa_sig_setup(
    backend: "Backend",
    padding: AsymmetricPadding,
    algorithm: typing.Optional[hashes.HashAlgorithm],
    key: typing.Union["_RSAPublicKey", "_RSAPrivateKey"],
    init_func: typing.Callable[[typing.Any], int],
):
    padding_enum = _rsa_sig_determine_padding(backend, key, padding, algorithm)
    pkey_ctx = backend._lib.EVP_PKEY_CTX_new(key._evp_pkey, backend._ffi.NULL)
    backend.openssl_assert(pkey_ctx != backend._ffi.NULL)
    pkey_ctx = backend._ffi.gc(pkey_ctx, backend._lib.EVP_PKEY_CTX_free)
    res = init_func(pkey_ctx)
    if res != 1:
        errors = backend._consume_errors()
        raise ValueError("Unable to sign/verify with this key", errors)

    if algorithm is not None:
        evp_md = backend._evp_md_non_null_from_algorithm(algorithm)
        res = backend._lib.EVP_PKEY_CTX_set_signature_md(pkey_ctx, evp_md)
        if res <= 0:
            backend._consume_errors()
            raise UnsupportedAlgorithm(
                "{} is not supported by this backend for RSA signing.".format(
                    algorithm.name
                ),
                _Reasons.UNSUPPORTED_HASH,
            )
    res = backend._lib.EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding_enum)
    if res <= 0:
        backend._consume_errors()
        raise UnsupportedAlgorithm(
            "{} is not supported for the RSA signature operation.".format(
                padding.name
            ),
            _Reasons.UNSUPPORTED_PADDING,
        )
    if isinstance(padding, PSS):
        assert isinstance(algorithm, hashes.HashAlgorithm)
        res = backend._lib.EVP_PKEY_CTX_set_rsa_pss_saltlen(
            pkey_ctx,
            _get_rsa_pss_salt_length(backend, padding, key, algorithm),
        )
        backend.openssl_assert(res > 0)

        mgf1_md = backend._evp_md_non_null_from_algorithm(
            padding._mgf._algorithm
        )
        res = backend._lib.EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, mgf1_md)
        backend.openssl_assert(res > 0)

    return pkey_ctx


def _rsa_sig_sign(
    backend: "Backend",
    padding: AsymmetricPadding,
    algorithm: hashes.HashAlgorithm,
    private_key: "_RSAPrivateKey",
    data: bytes,
) -> bytes:
    pkey_ctx = _rsa_sig_setup(
        backend,
        padding,
        algorithm,
        private_key,
        backend._lib.EVP_PKEY_sign_init,
    )
    buflen = backend._ffi.new("size_t *")
    res = backend._lib.EVP_PKEY_sign(
        pkey_ctx, backend._ffi.NULL, buflen, data, len(data)
    )
    backend.openssl_assert(res == 1)
    buf = backend._ffi.new("unsigned char[]", buflen[0])
    res = backend._lib.EVP_PKEY_sign(pkey_ctx, buf, buflen, data, len(data))
    if res != 1:
        errors = backend._consume_errors_with_text()
        raise ValueError(
            "Digest or salt length too long for key size. Use a larger key "
            "or shorter salt length if you are specifying a PSS salt",
            errors,
        )

    return backend._ffi.buffer(buf)[:]


def _rsa_sig_verify(
    backend: "Backend",
    padding: AsymmetricPadding,
    algorithm: hashes.HashAlgorithm,
    public_key: "_RSAPublicKey",
    signature: bytes,
    data: bytes,
) -> None:
    pkey_ctx = _rsa_sig_setup(
        backend,
        padding,
        algorithm,
        public_key,
        backend._lib.EVP_PKEY_verify_init,
    )
    res = backend._lib.EVP_PKEY_verify(
        pkey_ctx, signature, len(signature), data, len(data)
    )
    # The previous call can return negative numbers in the event of an
    # error. This is not a signature failure but we need to fail if it
    # occurs.
    backend.openssl_assert(res >= 0)
    if res == 0:
        backend._consume_errors()
        raise InvalidSignature


def _rsa_sig_recover(
    backend: "Backend",
    padding: AsymmetricPadding,
    algorithm: typing.Optional[hashes.HashAlgorithm],
    public_key: "_RSAPublicKey",
    signature: bytes,
) -> bytes:
    pkey_ctx = _rsa_sig_setup(
        backend,
        padding,
        algorithm,
        public_key,
        backend._lib.EVP_PKEY_verify_recover_init,
    )

    # Attempt to keep the rest of the code in this function as constant/time
    # as possible. See the comment in _enc_dec_rsa_pkey_ctx. Note that the
    # buflen parameter is used even though its value may be undefined in the
    # error case. Due to the tolerant nature of Python slicing this does not
    # trigger any exceptions.
    maxlen = backend._lib.EVP_PKEY_size(public_key._evp_pkey)
    backend.openssl_assert(maxlen > 0)
    buf = backend._ffi.new("unsigned char[]", maxlen)
    buflen = backend._ffi.new("size_t *", maxlen)
    res = backend._lib.EVP_PKEY_verify_recover(
        pkey_ctx, buf, buflen, signature, len(signature)
    )
    resbuf = backend._ffi.buffer(buf)[: buflen[0]]
    backend._lib.ERR_clear_error()
    # Assume that all parameter errors are handled during the setup phase and
    # any error here is due to invalid signature.
    if res != 1:
        raise InvalidSignature
    return resbuf


class _RSAPrivateKey(RSAPrivateKey):
    _evp_pkey: object
    _key_size: int

    def __init__(
        self,
        backend: "Backend",
        evp_pkey,
        *,
        unsafe_skip_rsa_key_validation: bool,
    ):
        res: int
        # RSA_check_key is slower in OpenSSL 3.0.0 due to improved
        # primality checking. In normal use this is unlikely to be a problem
        # since users don't load new keys constantly, but for TESTING we've
        # added an init arg that allows skipping the checks. You should not
        # use this in production code unless you understand the consequences.
        if not unsafe_skip_rsa_key_validation:
            pkey_ctx = backend._lib.EVP_PKEY_CTX_new(evp_pkey, backend._ffi.NULL)
            backend.openssl_assert(pkey_ctx != backend._ffi.NULL)
            pkey_ctx = backend._ffi.gc(pkey_ctx, backend._lib.EVP_PKEY_CTX_free)
            res = backend._lib.EVP_PKEY_check(pkey_ctx)
            if res != 1:
                errors = backend._consume_errors_with_text()
                raise ValueError("Invalid private key", errors)
            # 2 is prime and passes an RSA key check, so we also check
            # if p and q are odd just to be safe.
            p = backend._ffi.new("BIGNUM **")
            q = backend._ffi.new("BIGNUM **")
            p[0] = backend._ffi.NULL
            q[0] = backend._ffi.NULL
            res = backend._lib.EVP_PKEY_get_bn_param(evp_pkey, b"rsa-factor1", p)
            backend.openssl_assert(res == 1)
            res = backend._lib.EVP_PKEY_get_bn_param(evp_pkey, b"rsa-factor2", q)
            backend.openssl_assert(res == 1)
            backend.openssl_assert(p[0] != backend._ffi.NULL)
            backend.openssl_assert(q[0] != backend._ffi.NULL)
            p_val = backend._ffi.gc(p[0], backend._lib.BN_free)
            q_val = backend._ffi.gc(q[0], backend._lib.BN_free)
            p_odd = backend._lib.BN_is_odd(p_val)
            q_odd = backend._lib.BN_is_odd(q_val)
            if p_odd != 1 or q_odd != 1:
                errors = backend._consume_errors_with_text()
                raise ValueError("Invalid private key", errors)

        self._backend = backend
        self._evp_pkey = evp_pkey
        # Used for lazy blinding
        self._blinded = False
        self._blinding_lock = threading.Lock()
        self._key_size = self._backend._lib.EVP_PKEY_bits(evp_pkey)

    def _enable_blinding(self) -> None:
        # If you call blind on an already blinded RSA key OpenSSL will turn
        # it off and back on, which is a performance hit we want to avoid.
        if not self._blinded:
            with self._blinding_lock:
                self._non_threadsafe_enable_blinding()

    def _non_threadsafe_enable_blinding(self) -> None:
        # This is only a separate function to allow for testing to cover both
        # branches. It should never be invoked except through _enable_blinding.
        # Check if it's not True again in case another thread raced past the
        # first non-locked check.
        if not self._blinded:
            if not self._backend._lib.CRYPTOGRAPHY_OPENSSL_300_OR_GREATER:
                rsa_cdata = self._backend.EVP_PKEY_get0_RSA(self._evp_pkey)
                self._backend.openssl_assert(
                    rsa_cdata != self._backend._ffi.NULL
                )
                res = self._backend._lib.RSA_blinding_on(
                    rsa_cdata, self._backend._ffi.NULL
                )
                self._backend.openssl_assert(res == 1)
            self._blinded = True

    @property
    def key_size(self) -> int:
        return self._key_size

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        self._enable_blinding()
        key_size_bytes = (self.key_size + 7) // 8
        if key_size_bytes != len(ciphertext):
            raise ValueError("Ciphertext length must be equal to key size.")

        return _enc_dec_rsa(self._backend, self, ciphertext, padding)

    def public_key(self) -> RSAPublicKey:
        pparams = self._backend._ffi.new("OSSL_PARAM **")
        res = self._backend._lib.EVP_PKEY_todata(
            self._evp_pkey, self._backend._lib.EVP_PKEY_PUBLIC_KEY, pparams
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(pparams[0] != self._backend._ffi.NULL)

        params = self._backend._ffi.gc(
            pparams[0], self._backend._lib.OSSL_PARAM_free
        )

        ctx = self._backend._lib.EVP_PKEY_CTX_new_id(
            self._backend._lib.EVP_PKEY_RSA, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
        ctx = self._backend._ffi.gc(ctx, self._backend._lib.EVP_PKEY_CTX_free)

        res = self._backend._lib.EVP_PKEY_fromdata_init(ctx)
        self._backend.openssl_assert(res == 1)

        ppub_key = self._backend._ffi.new("EVP_PKEY **")
        res = self._backend._lib.EVP_PKEY_fromdata(
            ctx, ppub_key, self._backend._lib.EVP_PKEY_PUBLIC_KEY, params
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(ppub_key[0] != self._backend._ffi.NULL)

        pub_key = self._backend._ffi.gc(
            ppub_key[0], self._backend._lib.EVP_PKEY_free
        )

        return _RSAPublicKey(self._backend, pub_key)

    def private_numbers(self) -> RSAPrivateNumbers:
        pn = self._backend._ffi.new("BIGNUM **")
        pe = self._backend._ffi.new("BIGNUM **")
        pd = self._backend._ffi.new("BIGNUM **")
        pp = self._backend._ffi.new("BIGNUM **")
        pq = self._backend._ffi.new("BIGNUM **")
        pdmp1 = self._backend._ffi.new("BIGNUM **")
        pdmq1 = self._backend._ffi.new("BIGNUM **")
        piqmp = self._backend._ffi.new("BIGNUM **")

        for key, pbn in [
            (b"n", pn),
            (b"e", pe),
            (b"d", pd),
            (b"rsa-factor1", pp),
            (b"rsa-factor2", pq),
            (b"rsa-exponent1", pdmp1),
            (b"rsa-exponent2", pdmq1),
            (b"rsa-coefficient1", piqmp),
        ]:
            pbn[0] = self._backend._ffi.NULL
            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, key, pbn
            )
            self._backend.openssl_assert(res == 1)
            self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)

        n = self._backend._ffi.gc(pn[0], self._backend._lib.BN_free)
        e = self._backend._ffi.gc(pe[0], self._backend._lib.BN_free)
        d = self._backend._ffi.gc(pd[0], self._backend._lib.BN_free)
        p = self._backend._ffi.gc(pp[0], self._backend._lib.BN_free)
        q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
        dmp1 = self._backend._ffi.gc(pdmp1[0], self._backend._lib.BN_free)
        dmq1 = self._backend._ffi.gc(pdmq1[0], self._backend._lib.BN_free)
        iqmp = self._backend._ffi.gc(piqmp[0], self._backend._lib.BN_free)
        return RSAPrivateNumbers(
            p=self._backend._bn_to_int(p),
            q=self._backend._bn_to_int(q),
            d=self._backend._bn_to_int(d),
            dmp1=self._backend._bn_to_int(dmp1),
            dmq1=self._backend._bn_to_int(dmq1),
            iqmp=self._backend._bn_to_int(iqmp),
            public_numbers=RSAPublicNumbers(
                e=self._backend._bn_to_int(e),
                n=self._backend._bn_to_int(n),
            ),
        )

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        return self._backend._private_key_bytes(
            encoding,
            format,
            encryption_algorithm,
            self,
            self._evp_pkey,
        )

    def sign(
        self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        self._enable_blinding()
        data, algorithm = _calculate_digest_and_algorithm(data, algorithm)
        return _rsa_sig_sign(self._backend, padding, algorithm, self, data)


class _RSAPublicKey(RSAPublicKey):
    _evp_pkey: object
    _key_size: int

    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey
        self._key_size = self._backend._lib.EVP_PKEY_bits(evp_pkey)

    @property
    def key_size(self) -> int:
        return self._key_size

    def encrypt(self, plaintext: bytes, padding: AsymmetricPadding) -> bytes:
        return _enc_dec_rsa(self._backend, self, plaintext, padding)

    def public_numbers(self) -> RSAPublicNumbers:
        pn = self._backend._ffi.new("BIGNUM **")
        pe = self._backend._ffi.new("BIGNUM **")

        for key, pbn in [(b"n", pn), (b"e", pe)]:
            pbn[0] = self._backend._ffi.NULL
            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, key, pbn
            )
            self._backend.openssl_assert(res == 1)
            self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)
        n = self._backend._ffi.gc(pn[0], self._backend._lib.BN_free)
        e = self._backend._ffi.gc(pe[0], self._backend._lib.BN_free)
        return RSAPublicNumbers(
            e=self._backend._bn_to_int(e),
            n=self._backend._bn_to_int(n),
        )

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        return self._backend._public_key_bytes(
            encoding, format, self, self._evp_pkey
        )

    def verify(
        self,
        signature: bytes,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> None:
        data, algorithm = _calculate_digest_and_algorithm(data, algorithm)
        _rsa_sig_verify(
            self._backend, padding, algorithm, self, signature, data
        )

    def recover_data_from_signature(
        self,
        signature: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Optional[hashes.HashAlgorithm],
    ) -> bytes:
        if isinstance(algorithm, asym_utils.Prehashed):
            raise TypeError(
                "Prehashed is only supported in the sign and verify methods. "
                "It cannot be used with recover_data_from_signature."
            )
        return _rsa_sig_recover(
            self._backend, padding, algorithm, self, signature
        )
