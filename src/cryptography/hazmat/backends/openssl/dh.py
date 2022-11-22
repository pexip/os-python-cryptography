# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.backend import Backend


def _dh_params_dup(evp_pkey, backend: "Backend"):
    pparams = backend._ffi.new("OSSL_PARAM **")
    res = backend._lib.EVP_PKEY_todata(
        evp_pkey, backend._lib.EVP_PKEY_KEY_PARAMETERS, pparams
    )
    backend.openssl_assert(res == 1)
    backend.openssl_assert(pparams[0] != backend._ffi.NULL)

    params = backend._ffi.gc(pparams[0], backend._lib.OSSL_PARAM_free)

    ctx = backend._lib.EVP_PKEY_CTX_new(evp_pkey, backend._ffi.NULL)
    backend.openssl_assert(ctx != backend._ffi.NULL)
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_PKEY_CTX_free)

    res = backend._lib.EVP_PKEY_fromdata_init(ctx)
    backend.openssl_assert(res == 1)

    evp_ppkey = backend._ffi.new("EVP_PKEY **")
    res = backend._lib.EVP_PKEY_fromdata(
        ctx, evp_ppkey, backend._lib.EVP_PKEY_KEY_PARAMETERS, params
    )
    backend.openssl_assert(res == 1)
    backend.openssl_assert(evp_ppkey[0] != backend._ffi.NULL)

    evp_pkey = backend._ffi.gc(evp_ppkey[0], backend._lib.EVP_PKEY_free)

    return evp_pkey


class _DHParameters(dh.DHParameters):
    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def parameter_numbers(self) -> dh.DHParameterNumbers:
        pp = self._backend._ffi.new("BIGNUM **")
        pg = self._backend._ffi.new("BIGNUM **")
        pq = self._backend._ffi.new("BIGNUM **")

        for key, pbn in [
            (b"p", pp),
            (b"q", pq),
            (b"g", pg),
        ]:
            pbn[0] = self._backend._ffi.NULL
            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, key, pbn
            )
            if key != b"q":
                self._backend.openssl_assert(res == 1)
                self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)

        p = self._backend._ffi.gc(pp[0], self._backend._lib.BN_free)
        g = self._backend._ffi.gc(pg[0], self._backend._lib.BN_free)

        q_val: typing.Optional[int]
        q_val = None
        if pq[0] != self._backend._ffi.NULL:
            q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
            q_val = self._backend._bn_to_int(q)

        return dh.DHParameterNumbers(
            p=self._backend._bn_to_int(p),
            g=self._backend._bn_to_int(g),
            q=q_val,
        )

    def generate_private_key(self) -> dh.DHPrivateKey:
        return self._backend.generate_dh_private_key(self)

    def parameter_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.ParameterFormat,
    ) -> bytes:
        if encoding is serialization.Encoding.OpenSSH:
            raise TypeError("OpenSSH encoding is not supported")

        if format is not serialization.ParameterFormat.PKCS3:
            raise ValueError("Only PKCS3 serialization is supported")

        if encoding is serialization.Encoding.PEM:
            output_type = b"PEM"
        elif encoding is serialization.Encoding.DER:
            output_type = b"DER"
        else:
            raise TypeError("encoding must be an item from the Encoding enum")

        ctx = self._backend._lib.OSSL_ENCODER_CTX_new_for_pkey(
            self._evp_pkey,
            self._backend._lib.OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
            output_type,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL
        )
        self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
        ctx = self._backend._ffi.gc(
            ctx, self._backend._lib.OSSL_ENCODER_CTX_free
        )
        bio = self._backend._create_mem_bio_gc()
        res = self._backend._lib.OSSL_ENCODER_to_bio(ctx, bio)
        self._backend.openssl_assert(res == 1)
        return self._backend._read_mem_bio(bio)


class _DHPrivateKey(dh.DHPrivateKey):
    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey
        self._key_size = self._backend._lib.EVP_PKEY_bits(evp_pkey)

    @property
    def key_size(self) -> int:
        return self._key_size

    def private_numbers(self) -> dh.DHPrivateNumbers:
        pp = self._backend._ffi.new("BIGNUM **")
        pg = self._backend._ffi.new("BIGNUM **")
        pq = self._backend._ffi.new("BIGNUM **")
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
            if key != b"q":
                self._backend.openssl_assert(res == 1)
                self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)

        p = self._backend._ffi.gc(pp[0], self._backend._lib.BN_free)
        g = self._backend._ffi.gc(pg[0], self._backend._lib.BN_free)
        pub_key = self._backend._ffi.gc(ppub_key[0], self._backend._lib.BN_free)
        priv_key = self._backend._ffi.gc(ppriv_key[0], self._backend._lib.BN_free)

        q_val = None
        if pq[0] != self._backend._ffi.NULL:
            q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
            q_val = self._backend._bn_to_int(q)

        return dh.DHPrivateNumbers(
            public_numbers=dh.DHPublicNumbers(
                parameter_numbers=dh.DHParameterNumbers(
                    p=self._backend._bn_to_int(p),
                    g=self._backend._bn_to_int(g),
                    q=q_val,
                ),
                y=self._backend._bn_to_int(pub_key),
            ),
            x=self._backend._bn_to_int(priv_key),
        )

    def exchange(self, peer_public_key: dh.DHPublicKey) -> bytes:
        if not isinstance(peer_public_key, _DHPublicKey):
            raise TypeError("peer_public_key must be a DHPublicKey")

        ctx = self._backend._lib.EVP_PKEY_CTX_new(
            self._evp_pkey, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
        ctx = self._backend._ffi.gc(ctx, self._backend._lib.EVP_PKEY_CTX_free)
        res = self._backend._lib.EVP_PKEY_derive_init(ctx)
        self._backend.openssl_assert(res == 1)
        res = self._backend._lib.EVP_PKEY_derive_set_peer(
            ctx, peer_public_key._evp_pkey
        )
        # Invalid kex errors here in OpenSSL 3.0 because checks were moved
        # to EVP_PKEY_derive_set_peer
        self._exchange_assert(res == 1)
        keylen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.EVP_PKEY_derive(
            ctx, self._backend._ffi.NULL, keylen
        )
        # Invalid kex errors here in OpenSSL < 3
        self._exchange_assert(res == 1)
        self._backend.openssl_assert(keylen[0] > 0)
        buf = self._backend._ffi.new("unsigned char[]", keylen[0])
        res = self._backend._lib.EVP_PKEY_derive(ctx, buf, keylen)
        self._backend.openssl_assert(res == 1)

        key = self._backend._ffi.buffer(buf, keylen[0])[:]
        pad = self._backend._lib.EVP_PKEY_size(self._evp_pkey) - len(key)

        if pad > 0:
            key = (b"\x00" * pad) + key

        return key

    def _exchange_assert(self, ok: bool) -> None:
        if not ok:
            errors_with_text = self._backend._consume_errors_with_text()
            raise ValueError(
                "Error computing shared key.",
                errors_with_text,
            )

    def public_key(self) -> dh.DHPublicKey:
        pparams = self._backend._ffi.new("OSSL_PARAM **")
        res = self._backend._lib.EVP_PKEY_todata(
            self._evp_pkey, self._backend._lib.EVP_PKEY_PUBLIC_KEY, pparams
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(pparams[0] != self._backend._ffi.NULL)

        params = self._backend._ffi.gc(
            pparams[0], self._backend._lib.OSSL_PARAM_free
        )

        ctx = self._backend._lib.EVP_PKEY_CTX_new(
            self._evp_pkey, self._backend._ffi.NULL
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
        return _DHPublicKey(self._backend, pub_key)

    def parameters(self) -> dh.DHParameters:
        params = _dh_params_dup(self._evp_pkey, self._backend)
        return _DHParameters(self._backend, params)

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        if format is not serialization.PrivateFormat.PKCS8:
            raise ValueError(
                "DH private keys support only PKCS8 serialization"
            )
        if not self._backend._lib.Cryptography_HAS_EVP_PKEY_DHX:
            pq = self._backend._ffi.new("BIGNUM **")

            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, b"q", pq
            )
            if res == 1 and pq[0] != self._backend._ffi.NULL:
                _q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
                raise UnsupportedAlgorithm(
                    "DH X9.42 serialization is not supported",
                    _Reasons.UNSUPPORTED_SERIALIZATION,
                )

        return self._backend._private_key_bytes(
            encoding,
            format,
            encryption_algorithm,
            self,
            self._evp_pkey,
        )


class _DHPublicKey(dh.DHPublicKey):
    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey
        self._key_size = self._backend._lib.EVP_PKEY_bits(evp_pkey)

    @property
    def key_size(self) -> int:
        return self._key_size

    def public_numbers(self) -> dh.DHPublicNumbers:
        pp = self._backend._ffi.new("BIGNUM **")
        pg = self._backend._ffi.new("BIGNUM **")
        pq = self._backend._ffi.new("BIGNUM **")
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
            if key != b"q":
                self._backend.openssl_assert(res == 1)
                self._backend.openssl_assert(pbn[0] != self._backend._ffi.NULL)

        p = self._backend._ffi.gc(pp[0], self._backend._lib.BN_free)
        g = self._backend._ffi.gc(pg[0], self._backend._lib.BN_free)
        pub_key = self._backend._ffi.gc(ppub_key[0], self._backend._lib.BN_free)

        q_val = None
        if pq[0] != self._backend._ffi.NULL:
            q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
            q_val = self._backend._bn_to_int(q)

        return dh.DHPublicNumbers(
            parameter_numbers=dh.DHParameterNumbers(
                p=self._backend._bn_to_int(p),
                g=self._backend._bn_to_int(g),
                q=q_val,
            ),
            y=self._backend._bn_to_int(pub_key),
        )

    def parameters(self) -> dh.DHParameters:
        params = _dh_params_dup(self._evp_pkey, self._backend)
        return _DHParameters(self._backend, params)

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        if format is not serialization.PublicFormat.SubjectPublicKeyInfo:
            raise ValueError(
                "DH public keys support only "
                "SubjectPublicKeyInfo serialization"
            )

        if not self._backend._lib.Cryptography_HAS_EVP_PKEY_DHX:
            pq = self._backend._ffi.new("BIGNUM **")

            res = self._backend._lib.EVP_PKEY_get_bn_param(
                self._evp_pkey, b"q", pq
            )
            if res == 1 and pq[0] != self._backend._ffi.NULL:
                _q = self._backend._ffi.gc(pq[0], self._backend._lib.BN_free)
                raise UnsupportedAlgorithm(
                    "DH X9.42 serialization is not supported",
                    _Reasons.UNSUPPORTED_SERIALIZATION,
                )

        return self._backend._public_key_bytes(
            encoding, format, self, self._evp_pkey
        )
