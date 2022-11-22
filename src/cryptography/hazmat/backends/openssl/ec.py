# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography.exceptions import (
    InvalidSignature,
    UnsupportedAlgorithm,
    _Reasons,
)
from cryptography.hazmat.backends.openssl.utils import (
    _calculate_digest_and_algorithm,
    _evp_pkey_derive,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.backend import Backend


def _check_signature_algorithm(
    signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
) -> None:
    if not isinstance(signature_algorithm, ec.ECDSA):
        raise UnsupportedAlgorithm(
            "Unsupported elliptic curve signature algorithm.",
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
        )


def _ec_key_curve_sn(backend: "Backend", evp_pkey) -> str:
    value = backend._ffi.new("int *")
    res = backend._lib.EVP_PKEY_get_int_param(
        evp_pkey, b"decoded-from-explicit", value
    )
    backend.openssl_assert(res == 1);
    if value[0] == 1:
        raise ValueError(
            "ECDSA keys with explicit parameters are unsupported at this time"
        )

    buflen = backend._ffi.new("size_t *")
    backend._lib.EVP_PKEY_get_group_name(
        evp_pkey, backend._ffi.NULL, 0, buflen
    )
    buf = backend._ffi.new("char []", buflen[0] + 1)
    res = backend._lib.EVP_PKEY_get_group_name(
        evp_pkey, buf, buflen[0] + 1, buflen
    )
    backend.openssl_assert(res == 1)
    return backend._ffi.buffer(buf)[:buflen[0]].decode("ascii")


def _mark_asn1_named_ec_curve(backend: "Backend", evp_pkey):
    """
    Set the named curve flag on the EC_KEY. This causes OpenSSL to
    serialize EC keys along with their curve OID which makes
    deserialization easier.
    """

    res = backend._lib.EVP_PKEY_set_utf8_string_param(
        evp_pkey, b"encoding", b"named_curve"
    )
    backend.openssl_assert(res == 1)


def _check_key_infinity(backend: "Backend", evp_pkey) -> None:
    _, group = backend._ec_key_determine_group_get_func(
        evp_pkey
    )

    buflen = backend._ffi.new("size_t *")
    res = backend._lib.EVP_PKEY_get_octet_string_param(
        evp_pkey, b"pub", backend._ffi.NULL, 0, buflen
    )
    backend.openssl_assert(res == 1)
    buf = backend._ffi.new("unsigned char[]", buflen[0])
    res = backend._lib.EVP_PKEY_get_octet_string_param(
        evp_pkey, b"pub", buf, buflen[0], buflen
    )
    backend.openssl_assert(res == 1)

    point = backend._lib.EC_POINT_new(group)
    backend.openssl_assert(point != backend._ffi.NULL)
    point = backend._ffi.gc(point, backend._lib.EC_POINT_free)

    res = backend._lib.EC_POINT_oct2point(
        group, point, buf, buflen[0], backend._ffi.NULL
    )
    backend.openssl_assert(res == 1)

    if backend._lib.EC_POINT_is_at_infinity(group, point):
        raise ValueError(
            "Cannot load an EC public key where the point is at infinity"
        )


def _sn_to_elliptic_curve(backend: "Backend", sn: str) -> ec.EllipticCurve:
    try:
        return ec._CURVE_TYPES[sn]()
    except KeyError:
        raise UnsupportedAlgorithm(
            "{} is not a supported elliptic curve".format(sn),
            _Reasons.UNSUPPORTED_ELLIPTIC_CURVE,
        )


def _ecdsa_sig_sign(
    backend: "Backend", private_key: "_EllipticCurvePrivateKey", data: bytes
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
        raise ValueError("Signing with EC key failed", errors)

    return backend._ffi.buffer(buf)[:buflen[0]]


def _ecdsa_sig_verify(
    backend: "Backend",
    public_key: "_EllipticCurvePublicKey",
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


class _EllipticCurvePrivateKey(ec.EllipticCurvePrivateKey):
    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

        sn = _ec_key_curve_sn(backend, evp_pkey)
        self._curve = _sn_to_elliptic_curve(backend, sn)
        _mark_asn1_named_ec_curve(backend, evp_pkey)
        _check_key_infinity(backend, evp_pkey)

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._curve

    @property
    def key_size(self) -> int:
        return self.curve.key_size

    def exchange(
        self, algorithm: ec.ECDH, peer_public_key: ec.EllipticCurvePublicKey
    ) -> bytes:
        if not (
            self._backend.elliptic_curve_exchange_algorithm_supported(
                algorithm, self.curve
            )
        ):
            raise UnsupportedAlgorithm(
                "This backend does not support the ECDH algorithm.",
                _Reasons.UNSUPPORTED_EXCHANGE_ALGORITHM,
            )

        if peer_public_key.curve.name != self.curve.name:
            raise ValueError(
                "peer_public_key and self are not on the same curve"
            )

        return _evp_pkey_derive(self._backend, self._evp_pkey, peer_public_key)

    def public_key(self) -> ec.EllipticCurvePublicKey:
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
            self._backend._lib.EVP_PKEY_EC, self._backend._ffi.NULL
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

        return _EllipticCurvePublicKey(self._backend, pub_key)

    def private_numbers(self) -> ec.EllipticCurvePrivateNumbers:
        ppriv = self._backend._ffi.new("BIGNUM **")
        res = self._backend._lib.EVP_PKEY_get_bn_param(
            self._evp_pkey, b"priv", ppriv
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(ppriv[0] != self._backend._ffi.NULL)
        priv = self._backend._ffi.gc(ppriv[0], self._backend._lib.BN_free)
        private_value = self._backend._bn_to_int(priv)
        return ec.EllipticCurvePrivateNumbers(
            private_value=private_value,
            public_numbers=self.public_key().public_numbers(),
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
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> bytes:
        _check_signature_algorithm(signature_algorithm)
        data, _ = _calculate_digest_and_algorithm(
            data,
            signature_algorithm.algorithm,
        )
        return _ecdsa_sig_sign(self._backend, self, data)


class _EllipticCurvePublicKey(ec.EllipticCurvePublicKey):
    def __init__(self, backend: "Backend", evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

        sn = _ec_key_curve_sn(backend, evp_pkey)
        self._curve = _sn_to_elliptic_curve(backend, sn)
        _mark_asn1_named_ec_curve(backend, evp_pkey)
        _check_key_infinity(backend, evp_pkey)

    @property
    def curve(self) -> ec.EllipticCurve:
        return self._curve

    @property
    def key_size(self) -> int:
        return self.curve.key_size

    def public_numbers(self) -> ec.EllipticCurvePublicNumbers:
        get_func, group = self._backend._ec_key_determine_group_get_func(
            self._evp_pkey
        )

        buflen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.EVP_PKEY_get_octet_string_param(
            self._evp_pkey, b"pub", self._backend._ffi.NULL, 0, buflen
        )
        self._backend.openssl_assert(res == 1)
        buf = self._backend._ffi.new("unsigned char[]", buflen[0])
        res = self._backend._lib.EVP_PKEY_get_octet_string_param(
            self._evp_pkey, b"pub", buf, buflen[0], buflen
        )
        self._backend.openssl_assert(res == 1)

        point = self._backend._lib.EC_POINT_new(group)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)
        point = self._backend._ffi.gc(point, self._backend._lib.EC_POINT_free)

        res = self._backend._lib.EC_POINT_oct2point(
            group, point, buf, buflen[0], self._backend._ffi.NULL
        )
        self._backend.openssl_assert(res == 1)

        with self._backend._tmp_bn_ctx() as bn_ctx:
            bn_x = self._backend._lib.BN_CTX_get(bn_ctx)
            bn_y = self._backend._lib.BN_CTX_get(bn_ctx)

            res = get_func(group, point, bn_x, bn_y, bn_ctx)
            self._backend.openssl_assert(res == 1)

            x = self._backend._bn_to_int(bn_x)
            y = self._backend._bn_to_int(bn_y)

        return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=self._curve)

    def _encode_point(self, format: serialization.PublicFormat) -> bytes:
        if format is serialization.PublicFormat.CompressedPoint:
            conversion = self._backend._lib.POINT_CONVERSION_COMPRESSED
        else:
            assert format is serialization.PublicFormat.UncompressedPoint
            conversion = self._backend._lib.POINT_CONVERSION_UNCOMPRESSED

        _, group = self._backend._ec_key_determine_group_get_func(
            self._evp_pkey
        )

        buflen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.EVP_PKEY_get_octet_string_param(
            self._evp_pkey, b"pub", self._backend._ffi.NULL, 0, buflen
        )
        self._backend.openssl_assert(res == 1)
        buf = self._backend._ffi.new("unsigned char[]", buflen[0])
        res = self._backend._lib.EVP_PKEY_get_octet_string_param(
            self._evp_pkey, b"pub", buf, buflen[0], buflen
        )
        self._backend.openssl_assert(res == 1)

        point = self._backend._lib.EC_POINT_new(group)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)
        point = self._backend._ffi.gc(point, self._backend._lib.EC_POINT_free)

        res = self._backend._lib.EC_POINT_oct2point(
            group, point, buf, buflen[0], self._backend._ffi.NULL
        )
        self._backend.openssl_assert(res == 1)

        with self._backend._tmp_bn_ctx() as bn_ctx:
            buflen = self._backend._lib.EC_POINT_point2oct(
                group, point, conversion, self._backend._ffi.NULL, 0, bn_ctx
            )
            self._backend.openssl_assert(buflen > 0)
            buf = self._backend._ffi.new("char[]", buflen)
            res = self._backend._lib.EC_POINT_point2oct(
                group, point, conversion, buf, buflen, bn_ctx
            )
            self._backend.openssl_assert(buflen == res)

        return self._backend._ffi.buffer(buf)[:]

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        if (
            encoding is serialization.Encoding.X962
            or format is serialization.PublicFormat.CompressedPoint
            or format is serialization.PublicFormat.UncompressedPoint
        ):
            if encoding is not serialization.Encoding.X962 or format not in (
                serialization.PublicFormat.CompressedPoint,
                serialization.PublicFormat.UncompressedPoint,
            ):
                raise ValueError(
                    "X962 encoding must be used with CompressedPoint or "
                    "UncompressedPoint format"
                )

            return self._encode_point(format)
        else:
            return self._backend._public_key_bytes(
                encoding, format, self, self._evp_pkey
            )

    def verify(
        self,
        signature: bytes,
        data: bytes,
        signature_algorithm: ec.EllipticCurveSignatureAlgorithm,
    ) -> None:
        _check_signature_algorithm(signature_algorithm)
        data, _ = _calculate_digest_and_algorithm(
            data,
            signature_algorithm.algorithm,
        )
        _ecdsa_sig_verify(self._backend, self, signature, data)
