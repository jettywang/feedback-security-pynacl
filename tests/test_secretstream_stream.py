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
from __future__ import annotations

import struct

import pytest

from nacl import exceptions as exc
from nacl.bindings import crypto_secretstream as css
from nacl.secretstream import (
    ABYTES,
    DEFAULT_CHUNK_SIZE,
    HEADER_SIZE,
    LENGTH_PREFIX_SIZE,
    SecretStreamAuthenticationError,
    SecretStreamError,
    SecretStreamReader,
    SecretStreamStateError,
    SecretStreamTrailingDataError,
    SecretStreamTruncatedError,
    SecretStreamWriter,
)

TAG_FINAL = css.crypto_secretstream_xchacha20poly1305_TAG_FINAL
TAG_MESSAGE = css.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_REKEY = css.crypto_secretstream_xchacha20poly1305_TAG_REKEY


@pytest.fixture(scope="module")
def key() -> bytes:
    return css.crypto_secretstream_xchacha20poly1305_keygen()


def _build(
    key: bytes, data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> bytes:
    writer = SecretStreamWriter(key, chunk_size=chunk_size)
    wire = bytearray(writer.header)
    for start in range(0, len(data), 777):
        wire += writer.write(data[start : start + 777])
    wire += writer.finalize()
    assert writer.is_closed
    return bytes(wire)


def _feed_in_chunks(
    reader: SecretStreamReader, wire: bytes, chunk: int
) -> bytes:
    out = bytearray()
    for start in range(0, len(wire), chunk):
        out += reader.feed(wire[start : start + chunk])
    return bytes(out)


def test_roundtrip_small_feeds(key: bytes) -> None:
    data = bytes((i * 7) & 0xFF for i in range(12_800))
    wire = _build(key, data)

    reader = SecretStreamReader(key)
    got = _feed_in_chunks(reader, wire, 7)
    assert reader.header == wire[:HEADER_SIZE]
    # Framing lets the FINAL record authenticate as soon as its bytes
    # arrive, without waiting for an explicit end-of-input signal.
    assert reader.is_complete is True
    assert reader.end_input() == b""
    assert got + reader.read() == data
    assert reader.is_failed is False
    assert reader.last_tag == TAG_FINAL
    # end_input is idempotent once the FINAL record is authenticated.
    assert reader.end_input() == b""


def test_empty_archive_is_one_final_record(key: bytes) -> None:
    writer = SecretStreamWriter(key)
    wire = writer.header + writer.finalize()

    assert len(wire) == HEADER_SIZE + LENGTH_PREFIX_SIZE + ABYTES
    assert (
        struct.unpack("<I", wire[HEADER_SIZE : HEADER_SIZE + 4])[0] == ABYTES
    )

    reader = SecretStreamReader(key)
    assert reader.feed(wire) == b""
    assert reader.end_input() == b""
    assert reader.is_complete
    assert reader.chunks_decrypted == 1
    assert reader.last_tag == TAG_FINAL


def test_byte_at_a_time_feed(key: bytes) -> None:
    data = b"streaming upload payload" * 200
    wire = _build(key, data, chunk_size=13)

    reader = SecretStreamReader(key, chunk_size=13)
    got = b"".join(reader.feed(wire[i : i + 1]) for i in range(len(wire)))
    assert reader.end_input() == b""
    assert got + reader.read() == data
    assert reader.is_complete


@pytest.mark.parametrize(
    "cut",
    [0, 1, 5, HEADER_SIZE - 1, HEADER_SIZE, HEADER_SIZE + 1, 50, 123],
)
def test_truncated_never_reports_complete(key: bytes, cut: int) -> None:
    data = b"archive" * 500
    wire = _build(key, data)
    cut = min(cut, len(wire) - 1)

    reader = SecretStreamReader(key)
    reader.feed(wire[:cut])
    with pytest.raises(SecretStreamTruncatedError):
        reader.end_input()
    # The public surface makes the integrity conclusion unambiguous.
    assert reader.is_complete is False
    assert reader.is_failed
    # A failed reader must be discarded: every operation now raises.
    with pytest.raises(SecretStreamStateError):
        reader.feed(b"x")
    with pytest.raises(SecretStreamStateError):
        reader.end_input()
    with pytest.raises(SecretStreamStateError):
        reader.read()


def test_every_prefix_cut_is_rejected(key: bytes) -> None:
    data = b"abcdefgh" * 100
    wire = _build(key, data, chunk_size=8)
    for cut in range(0, len(wire)):
        reader = SecretStreamReader(key, chunk_size=8)
        reader.feed(wire[:cut])
        with pytest.raises(SecretStreamError):
            reader.end_input()
        assert not reader.is_complete
        assert reader.is_failed


def test_corrupted_record_fails_authentication(key: bytes) -> None:
    wire = _build(key, b"hello" * 100)
    for index in (HEADER_SIZE + 5, len(wire) // 2, len(wire) - 1):
        corrupted = bytearray(wire)
        corrupted[index] ^= 0x01
        reader = SecretStreamReader(key)
        with pytest.raises(SecretStreamAuthenticationError):
            reader.feed(bytes(corrupted))
            reader.end_input()
        assert reader.is_failed
        assert not reader.is_complete


def test_wrong_key_fails_authentication(key: bytes) -> None:
    wire = _build(key, b"secret archive")
    other = css.crypto_secretstream_xchacha20poly1305_keygen()
    reader = SecretStreamReader(other)
    with pytest.raises(SecretStreamAuthenticationError):
        reader.feed(wire)
        reader.end_input()
    assert reader.is_failed


def test_explicit_rekey_rotates_tags(key: bytes) -> None:
    writer = SecretStreamWriter(key)
    wire = writer.header + writer.write(b"a" * DEFAULT_CHUNK_SIZE)
    writer.rekey()
    wire += writer.write(b"b" * DEFAULT_CHUNK_SIZE)
    wire += writer.finalize()

    reader = SecretStreamReader(key)
    assert (
        reader.feed(wire)
        == b"a" * DEFAULT_CHUNK_SIZE + b"b" * DEFAULT_CHUNK_SIZE
    )
    assert reader.end_input() == b""
    assert reader.is_complete

    # Verify the on-wire tags with the raw libsodium pull binding.
    state = css.crypto_secretstream_xchacha20poly1305_state()
    css.crypto_secretstream_xchacha20poly1305_init_pull(
        state, wire[:HEADER_SIZE], key
    )
    position = HEADER_SIZE
    tags = []
    while position < len(wire):
        (length,) = struct.unpack(
            "<I", wire[position : position + LENGTH_PREFIX_SIZE]
        )
        position += LENGTH_PREFIX_SIZE
        _, tag = css.crypto_secretstream_xchacha20poly1305_pull(
            state, wire[position : position + length]
        )
        position += length
        tags.append(tag)
    assert tags == [TAG_MESSAGE, TAG_REKEY, TAG_FINAL]


def test_rekey_then_finalize_still_final(key: bytes) -> None:
    writer = SecretStreamWriter(key)
    writer.rekey()
    wire = writer.header + writer.finalize()
    reader = SecretStreamReader(key)
    reader.feed(wire)
    reader.end_input()
    assert reader.is_complete
    assert reader.last_tag == TAG_FINAL


def test_trailing_data_after_final_rejected(key: bytes) -> None:
    wire = _build(key, b"q" * 40, chunk_size=16)

    reader = SecretStreamReader(key, chunk_size=16)
    reader.feed(wire)
    assert reader.is_complete
    with pytest.raises(SecretStreamTrailingDataError):
        reader.feed(b"extra")
    assert reader.is_failed

    # A leftover prefix/body is also rejected at end_input.
    other = SecretStreamReader(key, chunk_size=16)
    other.feed(wire)
    other._buffer.extend(b"\x01")
    with pytest.raises(SecretStreamTrailingDataError):
        other.end_input()
    assert other.is_failed


def test_writer_rejects_use_after_finalize(key: bytes) -> None:
    writer = SecretStreamWriter(key)
    assert writer.is_closed is False
    writer.finalize()
    with pytest.raises(SecretStreamStateError):
        writer.write(b"x")
    with pytest.raises(SecretStreamStateError):
        writer.rekey()
    with pytest.raises(SecretStreamStateError):
        writer.finalize()


def test_reader_and_writer_hold_separate_states(key: bytes) -> None:
    writer = SecretStreamWriter(key)
    reader = SecretStreamReader(key)
    # The pull state does not even exist until the header is observed.
    assert reader._state is None
    assert isinstance(
        writer._state, css.crypto_secretstream_xchacha20poly1305_state
    )
    # Mutating one stream's lifecycle leaves the other untouched.
    writer.finalize()
    assert not reader.is_failed and not reader.is_complete


def test_read_size_limiting(key: bytes) -> None:
    # feed() returns each record's plaintext immediately; read() drains
    # whatever is still buffered, so retain the first feed's output.
    wire = _build(key, b"z" * 40, chunk_size=16)
    reader = SecretStreamReader(key, chunk_size=16)
    assert reader.feed(wire) == b"z" * 40
    assert reader.read() == b""

    # Exercise the size-limited read against a populated plaintext
    # buffer, the state read() is designed to drain.
    reader = SecretStreamReader(key, chunk_size=16)
    reader.feed(wire)
    reader._plaintext.extend(b"abcdefghij")
    assert reader.read(4) == b"abcd"
    assert reader.read(4) == b"efgh"
    assert reader.read() == b"ij"
    assert reader.read() == b""
    assert reader.is_complete
    reader.end_input()


def test_raw_libsodium_record_bodies_roundtrip(key: bytes) -> None:
    # Records produced by the wrapper are plain push() ciphertext behind
    # the length prefix, so a raw binding consumer can pull them.
    writer = SecretStreamWriter(key, chunk_size=32)
    wire = writer.header + writer.write(b"plain" * 20) + writer.finalize()

    state = css.crypto_secretstream_xchacha20poly1305_state()
    css.crypto_secretstream_xchacha20poly1305_init_pull(
        state, wire[:HEADER_SIZE], key
    )
    position = HEADER_SIZE
    joined = b""
    while position < len(wire):
        (length,) = struct.unpack(
            "<I", wire[position : position + LENGTH_PREFIX_SIZE]
        )
        position += LENGTH_PREFIX_SIZE
        message, tag = css.crypto_secretstream_xchacha20poly1305_pull(
            state, wire[position : position + length]
        )
        position += length
        joined += message
    assert joined == b"plain" * 20
    assert tag == TAG_FINAL


def test_raw_push_stream_is_readable(key: bytes) -> None:
    state = css.crypto_secretstream_xchacha20poly1305_state()
    header = css.crypto_secretstream_xchacha20poly1305_init_push(state, key)
    first = css.crypto_secretstream_xchacha20poly1305_push(state, b"x" * 32)
    last = css.crypto_secretstream_xchacha20poly1305_push(
        state, b"tail", tag=TAG_FINAL
    )
    wire = (
        header
        + struct.pack("<I", len(first))
        + first
        + struct.pack("<I", len(last))
        + last
    )
    reader = SecretStreamReader(key, chunk_size=32)
    assert reader.feed(wire) == b"x" * 32 + b"tail"
    assert reader.end_input() == b""
    assert reader.is_complete


def test_malformed_length_prefix_is_fatal(key: bytes) -> None:
    wire = _build(key, b"")
    bad = bytearray(wire)
    bad[HEADER_SIZE : HEADER_SIZE + 4] = struct.pack("<I", ABYTES - 1)
    reader = SecretStreamReader(key)
    with pytest.raises(SecretStreamAuthenticationError):
        reader.feed(bytes(bad))
    assert reader.is_failed


def test_huge_prefix_without_body_is_truncation(key: bytes) -> None:
    wire = _build(key, b"")
    bad = bytearray(wire)
    bad[HEADER_SIZE : HEADER_SIZE + 4] = struct.pack("<I", 10_000_000)
    reader = SecretStreamReader(key)
    reader.feed(bytes(bad))
    with pytest.raises(SecretStreamTruncatedError):
        reader.end_input()
    assert reader.is_failed


def test_invalid_constructor_arguments(key: bytes) -> None:
    with pytest.raises(exc.ValueError):
        SecretStreamWriter(b"short")
    with pytest.raises(exc.TypeError):
        SecretStreamWriter(bytearray(32))  # type: ignore[arg-type]
    with pytest.raises(exc.ValueError):
        SecretStreamWriter(key, chunk_size=0)
    with pytest.raises(exc.ValueError):
        SecretStreamWriter(key, chunk_size=-1)
    with pytest.raises(exc.TypeError):
        SecretStreamReader(key, chunk_size=True)
    with pytest.raises(exc.TypeError):
        SecretStreamWriter(key).write("not bytes")  # type: ignore[arg-type]
