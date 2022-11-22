# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography.exceptions import (
    InvalidSignature,
    UnsupportedAlgorithm,
    _Reasons,
)
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.ciphers.modes import CBC

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.backend import Backend
    from cryptography.hazmat.primitives import ciphers


class _CMACContext:
    def __init__(
        self,
        backend: "Backend",
        algorithm: "ciphers.BlockCipherAlgorithm",
        ctx=None,
    ) -> None:
        if not backend.cmac_algorithm_supported(algorithm):
            raise UnsupportedAlgorithm(
                "This backend does not support CMAC.",
                _Reasons.UNSUPPORTED_CIPHER,
            )

        self._backend = backend
        self._key = algorithm.key
        self._algorithm = algorithm
        self._output_length = algorithm.block_size // 8

        if ctx is None:
            registry = self._backend._cipher_registry
            adapter = registry[type(algorithm), CBC]

            evp_cipher = adapter(self._backend, algorithm, CBC)
            cipher_name = self._backend._lib.EVP_CIPHER_name(evp_cipher)

            evp_mac = self._backend._lib.EVP_MAC_fetch(
                self._backend._ffi.NULL,
                b"CMAC",
                self._backend._ffi.NULL
            )
            self._backend.openssl_assert(evp_mac != self._backend._ffi.NULL)
            evp_mac = self._backend._ffi.gc(
                evp_mac, self._backend._lib.EVP_MAC_free
            )

            ctx = self._backend._lib.EVP_MAC_CTX_new(evp_mac)
            self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
            ctx = self._backend._ffi.gc(ctx, self._backend._lib.EVP_MAC_CTX_free)

            bld = self._backend._lib.OSSL_PARAM_BLD_new();
            self._backend.openssl_assert(bld != self._backend._ffi.NULL)
            bld = self._backend._ffi.gc(bld, self._backend._lib.OSSL_PARAM_BLD_free)

            res = self._backend._lib.OSSL_PARAM_BLD_push_utf8_string(
                bld, b"cipher", cipher_name, 0
            )
            self._backend.openssl_assert(res == 1);

            params = self._backend._lib.OSSL_PARAM_BLD_to_param(bld)
            self._backend.openssl_assert(params != self._backend._ffi.NULL)
            params = self._backend._ffi.gc(
                params, self._backend._lib.OSSL_PARAM_free
            )

            key_ptr = self._backend._ffi.from_buffer(self._key)
            res = self._backend._lib.EVP_MAC_init(
                ctx, key_ptr, len(self._key), params
            )
            self._backend.openssl_assert(res == 1)

        self._ctx = ctx

    def update(self, data: bytes) -> None:
        res = self._backend._lib.EVP_MAC_update(self._ctx, data, len(data))
        self._backend.openssl_assert(res == 1)

    def finalize(self) -> bytes:
        buf = self._backend._ffi.new("unsigned char[]", self._output_length)
        length = self._backend._ffi.new("size_t *", self._output_length)
        res = self._backend._lib.EVP_MAC_final(
            self._ctx, buf, length, self._output_length
        )
        self._backend.openssl_assert(res == 1)

        self._ctx = None

        return self._backend._ffi.buffer(buf)[:length[0]]

    def copy(self) -> "_CMACContext":
        copied_ctx = self._backend._lib.EVP_MAC_CTX_dup(self._ctx)
        self._backend.openssl_assert(copied_ctx != self._backend._ffi.NULL)
        copied_ctx = self._backend._ffi.gc(
            copied_ctx, self._backend._lib.EVP_MAC_CTX_free
        )
        return _CMACContext(self._backend, self._algorithm, ctx=copied_ctx)

    def verify(self, signature: bytes) -> None:
        digest = self.finalize()
        if not constant_time.bytes_eq(digest, signature):
            raise InvalidSignature("Signature did not match digest.")
