# Copyright 2026 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""High level streaming wrappers around the libsodium secretstream.

The :mod:`nacl.bindings.crypto_secretstream` layer exposes the raw
``crypto_secretstream_xchacha20poly1305`` primitives but leaves all framing
and end-of-stream handling to the caller. An upload receiver that stops
reading as soon as its socket hits EOF therefore cannot tell a fully
authenticated archive from a truncated one: libsodium only attests the
archive as a whole once the record carrying the ``FINAL`` tag has been
authenticated.

This module provides two stateful, strictly separated stream objects:

* :class:`SecretStreamWriter` owns a push state and emits the libsodium
  header followed by framed ciphertext records.
* :class:`SecretStreamReader` owns a pull state, accepts arbitrarily
  sized byte chunks via :meth:`SecretStreamReader.feed` and only reports
  :attr:`~SecretStreamReader.is_complete` once a ``FINAL`` tagged record
  has been authenticated.

Wire format
-----------

The stream is the plain libsodium secretstream construction with one
thin, unambiguous record frame on top:

1. The libsodium
   :data:`~nacl.bindings.crypto_secretstream_xchacha20poly1305_HEADERBYTES`
   byte header, emitted verbatim.
2. Zero or more records, each consisting of a 4 byte little-endian
   length prefix followed by exactly that many bytes of *unmodified*
   libsodium secretstream ciphertext (the output of
   ``crypto_secretstream_xchacha20poly1305_push``). The prefix only tells
   the receiver where one authenticated record ends; it carries no
   cryptographic material of its own, and every record body is still
   authenticated end to end by libsodium.

Plaintext is split into fixed size records of
:data:`DEFAULT_CHUNK_SIZE` bytes. The last record carries the ``FINAL``
tag; an empty archive consists of a single empty ``FINAL`` record. The
length prefix is what lets a receiver recognize a full length ``FINAL``
record and reject any trailing bytes without guessing record boundaries.
"""

from __future__ import annotations

from typing import Final

from nacl import exceptions as exc
from nacl.bindings.crypto_secretstream import (
    crypto_secretstream_xchacha20poly1305_ABYTES as _ABYTES,
    crypto_secretstream_xchacha20poly1305_HEADERBYTES as _HEADERBYTES,
    crypto_secretstream_xchacha20poly1305_KEYBYTES as _KEYBYTES,
    crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX as _MESSAGE_MAX,
    crypto_secretstream_xchacha20poly1305_TAG_FINAL as _TAG_FINAL,
    crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as _TAG_MESSAGE,
    crypto_secretstream_xchacha20poly1305_TAG_REKEY as _TAG_REKEY,
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_init_push,
    crypto_secretstream_xchacha20poly1305_pull,
    crypto_secretstream_xchacha20poly1305_push,
    crypto_secretstream_xchacha20poly1305_state,
)

__all__ = [
    "ABYTES",
    "DEFAULT_CHUNK_SIZE",
    "HEADER_SIZE",
    "KEY_SIZE",
    "LENGTH_PREFIX_SIZE",
    "MAX_CHUNK_SIZE",
    "SecretStreamError",
    "SecretStreamAuthenticationError",
    "SecretStreamStateError",
    "SecretStreamTruncatedError",
    "SecretStreamTrailingDataError",
    "SecretStreamReader",
    "SecretStreamWriter",
]

#: Number of bytes libsodium adds to every encrypted record.
ABYTES: Final[int] = _ABYTES

#: Size of the stream header emitted before the first framed record.
HEADER_SIZE: Final[int] = _HEADERBYTES

#: Required length of a secretstream key.
KEY_SIZE: Final[int] = _KEYBYTES

#: Size in bytes of the little-endian record length prefix.
LENGTH_PREFIX_SIZE: Final[int] = 4

#: Default plaintext record size used when splitting a stream.
DEFAULT_CHUNK_SIZE: Final[int] = 4096

#: Largest plaintext record this framing can describe with the prefix.
MAX_CHUNK_SIZE: Final[int] = min(_MESSAGE_MAX, 0xFFFFFFFF - ABYTES)


def _frame(record: bytes) -> bytes:
    length = len(record).to_bytes(LENGTH_PREFIX_SIZE, "little")
    return length + record


class SecretStreamError(exc.CryptoError):
    """Base class for every error raised by this module."""


class SecretStreamStateError(SecretStreamError):
    """The stream object cannot accept the requested operation.

    Raised when a writer is used after :meth:`SecretStreamWriter.finalize`,
    when a reader is used after :meth:`SecretStreamReader.end_input` or an
    authentication failure, or when more data is fed to a reader whose
    ``FINAL`` record has already been consumed. A reader that raised this
    error (or any other :class:`SecretStreamError`) is poisoned and must be
    discarded: its libsodium state can no longer be trusted.
    """


class SecretStreamAuthenticationError(SecretStreamError):
    """A record failed authentication or its frame was malformed.

    The reader state is poisoned when this is raised and must be
    discarded.
    """


class SecretStreamTruncatedError(SecretStreamError):
    """The input ended before a ``FINAL`` tagged record was seen.

    Every record decrypted so far is authentic on its own, but the
    archive as a whole was never completed; its content must not be
    treated as a successful upload. The reader state is poisoned and
    must be discarded.
    """


class SecretStreamTrailingDataError(SecretStreamError):
    """Authenticated ``FINAL`` data was followed by additional bytes.

    The bytes following the ``FINAL`` record cannot belong to this
    stream, so the framing is corrupt. The reader state is poisoned and
    must be discarded.
    """


def _check_key(key: bytes) -> None:
    if not isinstance(key, bytes):
        raise exc.TypeError("Key must be a bytes sequence")
    if len(key) != KEY_SIZE:
        raise exc.ValueError(
            f"The key must be exactly {KEY_SIZE} bytes long",
        )


def _check_chunk_size(chunk_size: int) -> None:
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool):
        raise exc.TypeError("chunk_size must be an integer")
    if chunk_size <= 0:
        raise exc.ValueError("chunk_size must be positive")
    if chunk_size > MAX_CHUNK_SIZE:
        raise exc.ValueError(
            "chunk_size is larger than the framed message limit",
        )


class SecretStreamWriter:
    """Encrypt a byte stream with the libsodium secretstream construction.

    A writer owns a *push* state; it cannot decrypt anything. The stream
    is opened with a key and the resulting :attr:`header` must be
    transmitted first, followed by the bytes returned by :meth:`write`
    and finally by the bytes returned by :meth:`finalize`.

    Plaintext handed to :meth:`write` is buffered and split into records
    of ``chunk_size`` plaintext bytes. Every non-final record carries the
    ``MESSAGE`` tag (or ``REKEY`` after :meth:`rekey`); only the record
    emitted by :meth:`finalize` carries the ``FINAL`` tag. An empty
    archive therefore produces exactly one zero-length ``FINAL`` record.

    :param key: secret key of :data:`KEY_SIZE` bytes.
    :param chunk_size: plaintext bytes packed into each non-final record.
                       The reader has to use the same value.
    """

    def __init__(self, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
        _check_key(key)
        _check_chunk_size(chunk_size)
        self._chunk_size = chunk_size
        self._state = crypto_secretstream_xchacha20poly1305_state()
        self._header = crypto_secretstream_xchacha20poly1305_init_push(
            self._state, key
        )
        self._buffer = bytearray()
        self._rekey_pending = False
        self._closed = False

    @property
    def header(self) -> bytes:
        """The libsodium header that must prefix the ciphertext stream."""
        return self._header

    @property
    def chunk_size(self) -> int:
        """Plaintext bytes packed into each non-final record."""
        return self._chunk_size

    @property
    def is_closed(self) -> bool:
        """``True`` once :meth:`finalize` has been called."""
        return self._closed

    def _ensure_open(self) -> None:
        if self._closed:
            raise SecretStreamStateError(
                "Cannot write to a finalized secretstream writer",
            )

    def _push_record(self, record: bytes, final: bool) -> bytes:
        if final:
            tag = _TAG_FINAL
        elif self._rekey_pending:
            tag = _TAG_REKEY
        else:
            tag = _TAG_MESSAGE
        # libsodium clears the rekey flag as part of pushing the record,
        # including when FINAL is combined with a pending rekey.
        self._rekey_pending = False
        ciphertext = crypto_secretstream_xchacha20poly1305_push(
            self._state, record, None, tag
        )
        return _frame(ciphertext)

    def write(self, data: bytes) -> bytes:
        """Encrypt ``data`` and return the resulting framed ciphertext.

        ``data`` may be any size; full records are emitted immediately
        and a partial final record is buffered until more data arrives
        or :meth:`finalize` is called.
        """
        self._ensure_open()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise exc.TypeError("data must be a bytes-like object")
        self._buffer.extend(data)
        out = bytearray()
        while len(self._buffer) >= self._chunk_size:
            record = bytes(self._buffer[: self._chunk_size])
            del self._buffer[: self._chunk_size]
            out.extend(self._push_record(record, False))
        return bytes(out)

    def rekey(self) -> None:
        """Force the next emitted record to carry the ``REKEY`` tag.

        Forward secrecy is then explicit in the stream: a matching
        :class:`SecretStreamReader` rotates its state automatically while
        authenticating that record. Calling this several times before
        the next record is equivalent to calling it once.
        """
        self._ensure_open()
        self._rekey_pending = True

    def finalize(self) -> bytes:
        """Emit the framed ``FINAL`` record and close the writer.

        Any buffered plaintext becomes the final record (possibly
        empty). The returned bytes authenticate the whole archive and
        must be transmitted; without them the receiver can only observe
        a truncated stream.
        """
        self._ensure_open()
        last = self._push_record(bytes(self._buffer), True)
        self._buffer.clear()
        self._closed = True
        return last


class SecretStreamReader:
    """Decrypt a framed libsodium secretstream produced by a writer.

    A reader owns a *pull* state; it cannot encrypt anything. Ciphertext
    is fed through :meth:`feed` in arbitrarily sized pieces (including
    one byte at a time) and the decrypted plaintext is returned
    immediately. Integrity is only established once
    :meth:`end_input` has been called after a ``FINAL`` record was
    authenticated:

    * :attr:`is_complete` stays ``False`` while only ordinary records
      have been seen, so a receiver that hits EOF early can distinguish a
      truncated upload from a complete one.
    * Any authentication, framing or state failure poisons the reader.
      Every subsequent call raises :class:`SecretStreamStateError`; the
      object must be discarded and a fresh pull state created.

    :param key: secret key of :data:`KEY_SIZE` bytes.
    :param chunk_size: the record size the matching writer was configured
                       with. Record boundaries on the wire come from the
                       length prefixes, so this is retained for symmetry
                       and validation rather than used to split input.
    """

    def __init__(self, key: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
        _check_key(key)
        _check_chunk_size(chunk_size)
        self._chunk_size = chunk_size
        self._key = key
        self._state: crypto_secretstream_xchacha20poly1305_state | None = None
        self._buffer = bytearray()
        self._header: bytes | None = None
        self._plaintext = bytearray()
        self._last_tag: int | None = None
        self._complete = False
        self._failed = False
        self._chunks_seen = 0

    @property
    def header(self) -> bytes | None:
        """Stream header once enough bytes have been fed, else ``None``."""
        return self._header

    @property
    def chunk_size(self) -> int:
        """Record size the matching writer was configured with."""
        return self._chunk_size

    @property
    def is_complete(self) -> bool:
        """``True`` only after an authenticated ``FINAL`` record."""
        return self._complete

    @property
    def is_failed(self) -> bool:
        """``True`` once the state has been poisoned and must be discarded."""
        return self._failed

    @property
    def last_tag(self) -> int | None:
        """Tag of the last authenticated record, or ``None`` before any."""
        return self._last_tag

    @property
    def chunks_decrypted(self) -> int:
        """Number of fully authenticated records consumed so far."""
        return self._chunks_seen

    def _fail(self, error: SecretStreamError) -> SecretStreamError:
        self._failed = True
        return error

    def _ensure_live(self) -> None:
        if self._failed:
            raise SecretStreamStateError(
                "This secretstream reader has failed and must be discarded",
            )

    def _ensure_accepting(self) -> None:
        self._ensure_live()
        if self._complete:
            raise self._fail(
                SecretStreamTrailingDataError(
                    "No more data may follow the FINAL record",
                )
            )

    def _pull_record(self, record: bytes) -> tuple[bytes, int]:
        assert self._state is not None
        try:
            return crypto_secretstream_xchacha20poly1305_pull(
                self._state, record
            )
        except (exc.RuntimeError, exc.ValueError) as e:
            # A forged or rotated key fails the MAC check; a malformed or
            # cut record is rejected before that. Both poison the state.
            raise self._fail(
                SecretStreamAuthenticationError(
                    "Secretstream record failed authentication",
                )
            ) from e

    def _init_state(self) -> None:
        self._header = bytes(self._buffer[:HEADER_SIZE])
        del self._buffer[:HEADER_SIZE]
        self._state = crypto_secretstream_xchacha20poly1305_state()
        try:
            crypto_secretstream_xchacha20poly1305_init_pull(
                self._state, self._header, self._key
            )
        except exc.RuntimeError as e:
            raise self._fail(
                SecretStreamAuthenticationError(
                    "Secretstream header could not be initialized",
                )
            ) from e

    def _drain(self) -> None:
        if self._state is None:
            if len(self._buffer) < HEADER_SIZE:
                return
            self._init_state()

        while True:
            # Need a full length prefix before record boundaries are known.
            if len(self._buffer) < LENGTH_PREFIX_SIZE:
                return
            record_len = int.from_bytes(
                self._buffer[:LENGTH_PREFIX_SIZE], "little"
            )
            # ``record_len`` counts libsodium ciphertext bytes, i.e. the
            # plaintext record length plus ABYTES.
            if record_len < ABYTES or record_len > MAX_CHUNK_SIZE + ABYTES:
                raise self._fail(
                    SecretStreamAuthenticationError(
                        "Secretstream frame length is out of range",
                    )
                )
            framed_len = LENGTH_PREFIX_SIZE + record_len
            if len(self._buffer) < framed_len:
                # Wait for the rest of this record to arrive.
                return
            record = bytes(self._buffer[LENGTH_PREFIX_SIZE:framed_len])
            del self._buffer[:framed_len]
            message, tag = self._pull_record(record)
            self._plaintext.extend(message)
            self._last_tag = tag
            self._chunks_seen += 1
            # The four secretstream tags are enumerated values
            # (MESSAGE=0, PUSH=1, REKEY=2, FINAL=3), so FINAL is tested by
            # equality rather than as a bit flag: REKEY (2) would
            # otherwise match the low bits of FINAL (3).
            if tag == _TAG_FINAL:
                self._complete = True
                return

    def feed(self, data: bytes) -> bytes:
        """Consume ciphertext bytes and return any decrypted plaintext.

        Bytes are buffered internally until complete framed records can
        be authenticated. A truncated or forged record raises a
        :class:`SecretStreamError` and poisons the reader.
        """
        self._ensure_accepting()
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise exc.TypeError("data must be a bytes-like object")
        self._buffer.extend(data)
        self._drain()
        out = bytes(self._plaintext)
        self._plaintext.clear()
        return out

    def read(self, size: int | None = None) -> bytes:
        """Return at most ``size`` buffered plaintext bytes.

        Unlike :meth:`feed` this performs no decryption; it only drains
        plaintext already produced by earlier :meth:`feed` calls. With
        ``size`` omitted or negative every buffered byte is returned.
        """
        self._ensure_live()
        if size is None or size < 0:
            out = bytes(self._plaintext)
            self._plaintext.clear()
            return out
        out = bytes(self._plaintext[:size])
        del self._plaintext[:size]
        return out

    def end_input(self) -> bytes:
        """Signal that no more ciphertext will arrive.

        Raises :class:`SecretStreamTruncatedError` if the stream ended
        without an authenticated ``FINAL`` record and
        :class:`SecretStreamTrailingDataError` if bytes remain after it.
        On success :attr:`is_complete` is guaranteed to be ``True`` and
        further calls are idempotent no-ops. Plaintext is always
        delivered through :meth:`feed` or :meth:`read`.
        """
        self._ensure_live()
        if self._complete:
            if self._buffer:
                raise self._fail(
                    SecretStreamTrailingDataError(
                        "Data follows the FINAL secretstream record",
                    )
                )
            return b""

        # Not complete means the buffer still holds a cut header, a cut
        # length prefix or an unfinished record: in every case the FINAL
        # tag was never authenticated, so the upload is truncated.
        self._buffer.clear()
        raise self._fail(
            SecretStreamTruncatedError(
                "Stream ended before the FINAL record was authenticated",
            )
        )
