# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import typing

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl.utils import (
    _calculate_digest_and_algorithm,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.backend import Backend


def _dsa_sig_sign(
    backend: "Backend", private_key: "_DSAPrivateKey", data: bytes
) -> bytes:

    pctx = backend._lib.EVP_PKEY_CTX_new(
        private_key._evp_pkey, backend._ffi.NULL
    )
    backend.openssl_assert(pctx != backend._ffi.NULL)
    pctx = backend._ffi.gc(pctx, backend._lib.EVP_PKEY_CTX_free)
    res = backend._lib.EVP_PKEY_sign_init(pctx)
    if res != 1:
        errors = backend._consume_errors()
        raise ValueError("Unable to sign with this key", errors)

    buflen = backend._ffi.new("size_t *")
    res = backend._lib.EVP_PKEY_sign(
        pctx, backend._ffi.NULL, buflen, data, len(data)
    )
    backend.openssl_assert(res == 1)
    buf = backend._ffi.new("unsigned char[]", buflen[0])
    res = backend._lib.EVP_PKEY_sign(pctx, buf, buflen, data, len(data))
    if res != 1:
        errors = backend._consume_errors_with_text()
        raise ValueError("Signing with DSA key failed", errors)

    return backend._ffi.buffer(buf)[:buflen[0]]


def _dsa_sig_verify(
    backend: "Backend",
    public_key: "_DSAPublicKey",
    signature: bytes,
    data: bytes,
) -> None:
    pctx = backend._lib.EVP_PKEY_CTX_new(
        public_key._evp_pkey, backend._ffi.NULL
    )
    backend.openssl_assert(pctx != backend._ffi.NULL)
    pctx = backend._ffi.gc(pctx, backend._lib.EVP_PKEY_CTX_free)
    res = backend._lib.EVP_PKEY_verify_init(pctx)
    if res != 1:
        errors = backend._consume_errors()
        raise ValueError("Unable to verify with this key", errors)

    res = backend._lib.EVP_PKEY_verify(
        pctx, signature, len(signature), data, len(data)
    )
    if res != 1:
        backend._consume_errors()
        raise InvalidSignature


class _DSAParameters(dsa.DSAParameters):
    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def parameter_numbers(self) -> dsa.DSAParameterNumbers:
        pp = self._backend._ffi.new("BIGNUM **")
        pq = self._backend._ffi.new("BIGNUM **")
        pg = self._backend._ffi.new("BIGNUM **")

        for key, pbn in [
            (b"p", pp),
            (b"q", pq),
            (b"g", pg),
        ]:
            pbn[0] = self._backend._ffi.NULL
            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, key, pbn
            )
            self._backend.openssl_assert(res == 1)
            self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)

        p = self._backend._ffi.gc(pp[0], self._backend._lib.BN_free)
        q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
        g = self._backend._ffi.gc(pg[0], self._backend._lib.BN_free)

        return dsa.DSAParameterNumbers(
            p=self._backend._bn_to_int(p),
            q=self._backend._bn_to_int(q),
            g=self._backend._bn_to_int(g),
        )

    def generate_private_key(self) -> dsa.DSAPrivateKey:
        return self._backend.generate_dsa_private_key(self)


class _DSAPrivateKey(dsa.DSAPrivateKey):
    _key_size: int

    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey
        self._key_size = self._backend._lib.EVP_PKEY_bits(evp_pkey)

    @property
    def key_size(self) -> int:
        return self._key_size

    def private_numbers(self) -> dsa.DSAPrivateNumbers:
        pp = self._backend._ffi.new("BIGNUM **")
        pq = self._backend._ffi.new("BIGNUM **")
        pg = self._backend._ffi.new("BIGNUM **")
        ppub_key = self._backend._ffi.new("BIGNUM **")
        ppriv_key = self._backend._ffi.new("BIGNUM **")

        for key, pbn in [
            (b"p", pp),
            (b"q", pq),
            (b"g", pg),
            (b"pub", ppub_key),
            (b"priv", ppriv_key),
        ]:
            pbn[0] = self._backend._ffi.NULL
            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, key, pbn
            )
            self._backend.openssl_assert(res == 1)
            self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)

        p = self._backend._ffi.gc(pp[0], self._backend._lib.BN_free)
        q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
        g = self._backend._ffi.gc(pg[0], self._backend._lib.BN_free)
        pub_key = self._backend._ffi.gc(ppub_key[0], self._backend._lib.BN_free)
        priv_key = self._backend._ffi.gc(ppriv_key[0], self._backend._lib.BN_free)
        return dsa.DSAPrivateNumbers(
            public_numbers=dsa.DSAPublicNumbers(
                parameter_numbers=dsa.DSAParameterNumbers(
                    p=self._backend._bn_to_int(p),
                    q=self._backend._bn_to_int(q),
                    g=self._backend._bn_to_int(g),
                ),
                y=self._backend._bn_to_int(pub_key),
            ),
            x=self._backend._bn_to_int(priv_key),
        )

    def public_key(self) -> dsa.DSAPublicKey:
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
            self._backend._lib.EVP_PKEY_DSA, self._backend._ffi.NULL
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

        return _DSAPublicKey(self._backend, pub_key)

    def parameters(self) -> dsa.DSAParameters:
        pparams = self._backend._ffi.new("OSSL_PARAM **")
        res = self._backend._lib.EVP_PKEY_todata(
            self._evp_pkey, self._backend._lib.EVP_PKEY_KEY_PARAMETERS, pparams
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(pparams[0] != self._backend._ffi.NULL)

        params = self._backend._ffi.gc(
            pparams[0], self._backend._lib.OSSL_PARAM_free
        )

        ctx = self._backend._lib.EVP_PKEY_CTX_new_id(
            self._backend._lib.EVP_PKEY_DSA, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
        ctx = self._backend._ffi.gc(ctx, self._backend._lib.EVP_PKEY_CTX_free)

        res = self._backend._lib.EVP_PKEY_fromdata_init(ctx)
        self._backend.openssl_assert(res == 1)

        evp_ppkey = self._backend._ffi.new("EVP_PKEY **")
        res = self._backend._lib.EVP_PKEY_fromdata(
            ctx, evp_ppkey, self._backend._lib.EVP_PKEY_KEY_PARAMETERS, params
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(evp_ppkey[0] != self._backend._ffi.NULL)

        evp_pkey = self._backend._ffi.gc(
            evp_ppkey[0], self._backend._lib.EVP_PKEY_free
        )

        return _DSAParameters(self._backend, evp_pkey)

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
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:
        data, _ = _calculate_digest_and_algorithm(data, algorithm)
        return _dsa_sig_sign(self._backend, self, data)


class _DSAPublicKey(dsa.DSAPublicKey):
    _key_size: int

    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey
        self._key_size = self._backend._lib.EVP_PKEY_bits(evp_pkey)

    @property
    def key_size(self) -> int:
        return self._key_size

    def public_numbers(self) -> dsa.DSAPublicNumbers:
        pp = self._backend._ffi.new("BIGNUM **")
        pq = self._backend._ffi.new("BIGNUM **")
        pg = self._backend._ffi.new("BIGNUM **")
        ppub_key = self._backend._ffi.new("BIGNUM **")

        for key, pbn in [
            (b"p", pp),
            (b"q", pq),
            (b"g", pg),
            (b"pub", ppub_key),
        ]:
            pbn[0] = self._backend._ffi.NULL
            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, key, pbn
            )
            self._backend.openssl_assert(res == 1)
            self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)

        p = self._backend._ffi.gc(pp[0], self._backend._lib.BN_free)
        q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
        g = self._backend._ffi.gc(pg[0], self._backend._lib.BN_free)
        pub_key = self._backend._ffi.gc(ppub_key[0], self._backend._lib.BN_free)

        return dsa.DSAPublicNumbers(
            parameter_numbers=dsa.DSAParameterNumbers(
                p=self._backend._bn_to_int(p),
                q=self._backend._bn_to_int(q),
                g=self._backend._bn_to_int(g),
            ),
            y=self._backend._bn_to_int(pub_key),
        )

    def parameters(self) -> dsa.DSAParameters:
        pparams = self._backend._ffi.new("OSSL_PARAM **")
        res = self._backend._lib.EVP_PKEY_todata(
            self._evp_pkey, self._backend._lib.EVP_PKEY_KEY_PARAMETERS, pparams
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(pparams[0] != self._backend._ffi.NULL)

        params = self._backend._ffi.gc(
            pparams[0], self._backend._lib.OSSL_PARAM_free
        )

        ctx = self._backend._lib.EVP_PKEY_CTX_new_id(
            self._backend._lib.EVP_PKEY_DSA, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
        ctx = self._backend._ffi.gc(ctx, self._backend._lib.EVP_PKEY_CTX_free)

        res = self._backend._lib.EVP_PKEY_fromdata_init(ctx)
        self._backend.openssl_assert(res == 1)

        evp_ppkey = self._backend._ffi.new("EVP_PKEY **")
        res = self._backend._lib.EVP_PKEY_fromdata(
            ctx, evp_ppkey, self._backend._lib.EVP_PKEY_KEY_PARAMETERS, params
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(evp_ppkey[0] != self._backend._ffi.NULL)

        evp_pkey = self._backend._ffi.gc(
            evp_ppkey[0], self._backend._lib.EVP_PKEY_free
        )

        return _DSAParameters(self._backend, evp_pkey)

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
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> None:
        data, _ = _calculate_digest_and_algorithm(data, algorithm)
        return _dsa_sig_verify(self._backend, self, signature, data)
