# Copyright 2016 Donald Stufft and individual contributors
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

import binascii
import copy
import hashlib
import json
import os
from typing import AnyStr

import pytest

import nacl.bindings
import nacl.encoding
import nacl.exceptions as exc
import nacl.hash
import nacl.hashlib

from .utils import read_crypto_test_vectors

# Fixed parameters for branched keyed BLAKE2b regression tests. Keeping them
# fixed lets each expected digest be computed independently with hashlib.
BRANCH_KEY = b"0123456789abcdef0123456789abcdef"
BRANCH_SALT = b"branch-salt-16b!"
BRANCH_PERSON = b"branch-person-16"
BRANCH_DIGEST_SIZE = 48
BRANCH_HEADER = b"audit-service:common-header\n"
BRANCH_CHUNKS = {
    b"branch-a": [b"record=1;", b"scope=read;", b"payload=alpha;"],
    b"branch-b": [b"record=2;", b"scope=write;", b"payload=beta;"],
    b"branch-c": [b"record=3;", b"scope=admin;", b"payload=gamma;"],
}

OVERLONG_PARAMS_VECTORS = [
    (b"key", 65 * b"\xaa", 16 * b"\xaa", 16 * b"\x55", 64, b"will raise"),
    (b"salt", b"key", 17 * b"\xaa", 16 * b"\x55", 64, b"will raise"),
    (b"personal", b"key", 16 * b"\xaa", 17 * b"\x55", 64, b"will raise"),
    (b"digest_size", b"key", 16 * b"\xaa", 16 * b"\x55", 65, b"will raise"),
]


def generichash_vectors() -> list[tuple[bytes, bytes, bytes, bytes]]:
    # Format: <message> <tab> <key> <tab> <output length> <tab> <output>
    DATA = "crypto-test-vectors-blake2-nosalt-nopersonalization.txt"
    # Type safety: read_crypto_test_vectors returns an arbitrary length tuple, but we
    # know this file's test entries contain exactly four fields.
    return read_crypto_test_vectors(DATA, delimiter=b"\t")  # type: ignore[return-value]


def blake2_salt_pers_vectors() -> list[
    tuple[bytes, bytes, bytes, bytes, bytes, bytes]
]:
    # Format: <message> <tab> <key> <tab> <salt> <tab>
    # <personalization> <tab> <output length> <tab> <output>
    DATA = "crypto-test-vectors-blake2-salt-personalization.txt"
    # Type safety: read_crypto_test_vectors returns an arbitrary length tuple, but we
    # know this file's test entries contain exactly six fields.
    return read_crypto_test_vectors(DATA, delimiter=b"\t")  # type: ignore[return-value]


def blake2_reference_vectors() -> list[tuple[str, str, int, str]]:
    DATA = "blake2-kat.json"
    path = os.path.join(os.path.dirname(__file__), "data", DATA)
    with open(path) as f:
        jvectors: list[dict[str, str]] = json.load(f)
    vectors = [
        (x["in"], x["key"], len(x["out"]) // 2, x["out"])
        for x in jvectors
        if x["hash"] == "blake2b"
    ]
    return vectors


@pytest.mark.parametrize(
    ["message", "key", "outlen", "output"], generichash_vectors()
)
def test_generichash(
    message: AnyStr, key: AnyStr, outlen: AnyStr | int, output: AnyStr
):
    msg = binascii.unhexlify(message)
    output_bytes = binascii.hexlify(binascii.unhexlify(output))
    k = binascii.unhexlify(key)
    outlen_parsed = int(outlen)
    out = nacl.hash.generichash(msg, digest_size=outlen_parsed, key=k)
    assert out == output_bytes


@pytest.mark.parametrize(
    ["message", "key", "salt", "person", "outlen", "output"],
    OVERLONG_PARAMS_VECTORS,
)
def test_overlong_blake2b_oneshot_params(
    message: bytes,
    key: bytes,
    salt: bytes,
    person: bytes,
    outlen: int,
    output: bytes,
):
    with pytest.raises(exc.ValueError):
        nacl.hash.blake2b(
            message, digest_size=outlen, key=key, salt=salt, person=person
        )


@pytest.mark.parametrize(
    ["message", "key", "outlen", "output"], blake2_reference_vectors()
)
def test_generichash_blake2_ref(
    message: str, key: str, outlen: int, output: str
):
    test_generichash(message, key, outlen, output)


@pytest.mark.parametrize(
    ["message", "key", "salt", "person", "outlen", "output"],
    blake2_salt_pers_vectors(),
)
def test_hash_blake2b(
    message: bytes,
    key: bytes,
    salt: bytes,
    person: bytes,
    outlen: bytes,
    output: bytes,
):
    msg = binascii.unhexlify(message)
    output = binascii.hexlify(binascii.unhexlify(output))
    k = binascii.unhexlify(key)
    slt = binascii.unhexlify(salt)
    pers = binascii.unhexlify(person)
    outlen_parsed = int(outlen)
    out = nacl.hash.blake2b(
        msg, digest_size=outlen_parsed, key=k, salt=slt, person=pers
    )
    assert out == output


def test_expected_hashlib_level_pickle_and_copy_failures():
    h = nacl.hashlib.blake2b()
    with pytest.raises(TypeError):
        copy.deepcopy(h)
    with pytest.raises(TypeError):
        copy.copy(h)


def test_expected_bindings_level_pickle_and_copy_failures():
    from nacl.bindings.crypto_generichash import (
        Blake2State,
        crypto_generichash_BYTES,
    )

    st = Blake2State(crypto_generichash_BYTES)
    with pytest.raises(TypeError):
        copy.deepcopy(st)
    with pytest.raises(TypeError):
        copy.copy(st)


@pytest.mark.parametrize(
    ["message", "key", "outlen", "output"], blake2_reference_vectors()
)
def test_hashlib_blake2_ref_vectors(
    message: str, key: str, outlen: int, output: str
):
    msg = binascii.unhexlify(message)
    k = binascii.unhexlify(key)
    outlen = int(outlen)
    out = binascii.unhexlify(output)
    h = nacl.hashlib.blake2b(msg, digest_size=outlen, key=k)
    dgst = h.digest()
    assert out == dgst


@pytest.mark.parametrize(
    ["message", "key", "outlen", "output"], blake2_reference_vectors()
)
def test_hashlib_blake2_iuf_ref_vectors(
    message: str, key: str, outlen: int, output: str
):
    msg = binascii.unhexlify(message)
    k = binascii.unhexlify(key)
    outlen = int(outlen)
    out = binascii.unhexlify(output)
    h = nacl.hashlib.blake2b(digest_size=outlen, key=k)
    for _pos in range(len(msg)):
        _end = _pos + 1
        h.update(bytes(msg[_pos:_end]))
    dgst = h.digest()
    hdgst = h.hexdigest()
    assert hdgst == output
    assert out == dgst


@pytest.mark.parametrize(
    ["message", "key", "outlen", "output"], blake2_reference_vectors()
)
def test_hashlib_blake2_iuf_cp_ref_vectors(
    message: str, key: str, outlen: int, output: str
):
    msg = binascii.unhexlify(message)
    msglen = len(msg)
    if msglen < 2:
        pytest.skip("Message too short for splitting")
    k = binascii.unhexlify(key)
    outlen = int(outlen)
    out = binascii.unhexlify(output)
    h = nacl.hashlib.blake2b(digest_size=outlen, key=k)
    for _pos in range(len(msg)):
        _end = _pos + 1
        h.update(bytes(msg[_pos:_end]))
        if _end == msglen // 2:
            h2 = h.copy()
    dgst = h.digest()
    d2 = h2.digest()
    assert out == dgst
    assert d2 != dgst


@pytest.mark.parametrize(
    ["message", "key", "salt", "person", "outlen", "output"],
    OVERLONG_PARAMS_VECTORS,
)
def test_overlong_blake2b_iuf_params(
    message: bytes,
    key: bytes,
    salt: bytes,
    person: bytes,
    outlen: int,
    output: bytes,
):
    with pytest.raises(exc.ValueError):
        nacl.hashlib.blake2b(
            message, digest_size=outlen, key=key, salt=salt, person=person
        )


def test_blake2_descriptors_presence():
    h = nacl.hashlib.blake2b()
    assert h.name == "blake2b"
    assert h.block_size == 128
    assert h.digest_size == 32  # this is the default digest_size


def test_blake2_digest_size_descriptor_coherence():
    h = nacl.hashlib.blake2b(digest_size=64)
    assert h.name == "blake2b"
    assert h.block_size == 128
    assert h.digest_size == 64


def _stdlib_blake2b(data: bytes) -> bytes:
    return hashlib.blake2b(
        data,
        digest_size=BRANCH_DIGEST_SIZE,
        key=BRANCH_KEY,
        salt=BRANCH_SALT,
        person=BRANCH_PERSON,
    ).digest()


def test_hashlib_blake2b_branches_digest_repeatedly_without_alias():
    original = nacl.hashlib.blake2b(
        BRANCH_HEADER,
        digest_size=BRANCH_DIGEST_SIZE,
        key=BRANCH_KEY,
        salt=BRANCH_SALT,
        person=BRANCH_PERSON,
    )
    original_digest = original.digest()
    assert original_digest == _stdlib_blake2b(BRANCH_HEADER)

    branches = {name: original.copy() for name in BRANCH_CHUNKS}
    messages = {name: BRANCH_HEADER for name in BRANCH_CHUNKS}

    # Start every branch from the same audited header.
    for name, chunks in BRANCH_CHUNKS.items():
        branches[name].update(chunks[0])
        messages[name] += chunks[0]

    # One branch asks for its digest several times early. The high-level
    # digest is computed from a state copy and leaves that branch usable.
    early_digest = branches[b"branch-a"].digest()
    assert branches[b"branch-a"].digest() == early_digest
    assert branches[b"branch-a"].digest() == early_digest
    assert branches[b"branch-a"].hexdigest() == binascii.hexlify(
        early_digest
    ).decode("ascii")
    assert early_digest == _stdlib_blake2b(messages[b"branch-a"])

    # Producing branch-a's digest must not move the original state or its
    # other copies.
    assert original.digest() == original_digest
    assert branches[b"branch-b"].digest() == _stdlib_blake2b(
        messages[b"branch-b"]
    )

    # Continue the other branches before advancing the paused branch.
    for name in (b"branch-b", b"branch-c"):
        branches[name].update(BRANCH_CHUNKS[name][1])
        messages[name] += BRANCH_CHUNKS[name][1]
        assert branches[name].digest() == _stdlib_blake2b(messages[name])

    assert branches[b"branch-a"].digest() == early_digest

    # Finish with deliberately interleaved updates.
    branches[b"branch-c"].update(BRANCH_CHUNKS[b"branch-c"][2])
    messages[b"branch-c"] += BRANCH_CHUNKS[b"branch-c"][2]
    branches[b"branch-a"].update(BRANCH_CHUNKS[b"branch-a"][1])
    messages[b"branch-a"] += BRANCH_CHUNKS[b"branch-a"][1]
    branches[b"branch-b"].update(BRANCH_CHUNKS[b"branch-b"][2])
    messages[b"branch-b"] += BRANCH_CHUNKS[b"branch-b"][2]
    branches[b"branch-a"].update(BRANCH_CHUNKS[b"branch-a"][2])
    messages[b"branch-a"] += BRANCH_CHUNKS[b"branch-a"][2]

    branch_digests = {}
    for name, stream in branches.items():
        branch_digests[name] = stream.digest()
        assert branch_digests[name] == _stdlib_blake2b(messages[name])

    assert len(set(branch_digests.values())) == len(branch_digests)
    assert original.digest() == original_digest


def test_generichash_blake2b_state_copies_own_independent_native_buffers():
    from nacl._sodium import ffi

    base = nacl.bindings.crypto_generichash_blake2b_init(
        key=BRANCH_KEY,
        salt=BRANCH_SALT,
        person=BRANCH_PERSON,
        digest_size=BRANCH_DIGEST_SIZE,
    )
    nacl.bindings.crypto_generichash_blake2b_update(base, BRANCH_HEADER)

    branches = {name: base.copy() for name in BRANCH_CHUNKS}
    states = [base, *branches.values()]
    addresses = {
        int(ffi.cast("uintptr_t", state._statebuf)) for state in states
    }
    assert len(addresses) == len(states)

    messages = {name: BRANCH_HEADER for name in BRANCH_CHUNKS}

    # Interleave updates to each independent native buffer.
    rounds = len(next(iter(BRANCH_CHUNKS.values())))
    for round_index in range(rounds):
        for name, chunks in BRANCH_CHUNKS.items():
            nacl.bindings.crypto_generichash_blake2b_update(
                branches[name], chunks[round_index]
            )
            messages[name] += chunks[round_index]

        if round_index == 0:
            unaffected = {
                name: state.copy()
                for name, state in branches.items()
                if name != b"branch-a"
            }
            snapshot_messages = dict(messages)

    branch_digests = {}
    for name, state in branches.items():
        branch_digests[name] = nacl.bindings.crypto_generichash_blake2b_final(
            state
        )
        assert branch_digests[name] == _stdlib_blake2b(messages[name])

    assert len(set(branch_digests.values())) == len(branch_digests)

    for name, state in unaffected.items():
        assert nacl.bindings.crypto_generichash_blake2b_final(
            state
        ) == _stdlib_blake2b(snapshot_messages[name])

    # The original prefix state was not finalized or modified by branches.
    assert nacl.bindings.crypto_generichash_blake2b_final(
        base
    ) == _stdlib_blake2b(BRANCH_HEADER)


def test_generichash_blake2b_final_consumes_state_but_copy_preserves_stream():
    state = nacl.bindings.crypto_generichash_blake2b_init(
        key=BRANCH_KEY,
        salt=BRANCH_SALT,
        person=BRANCH_PERSON,
        digest_size=BRANCH_DIGEST_SIZE,
    )
    nacl.bindings.crypto_generichash_blake2b_update(state, BRANCH_HEADER)

    # A snapshot can produce an intermediate digest while the live stream
    # remains available for further updates.
    snapshot = state.copy()
    assert nacl.bindings.crypto_generichash_blake2b_final(
        snapshot
    ) == _stdlib_blake2b(BRANCH_HEADER)

    tail = BRANCH_CHUNKS[b"branch-a"][0]
    nacl.bindings.crypto_generichash_blake2b_update(state, tail)
    assert nacl.bindings.crypto_generichash_blake2b_final(
        state
    ) == _stdlib_blake2b(BRANCH_HEADER + tail)

    finalized = nacl.bindings.crypto_generichash_blake2b_init(
        key=BRANCH_KEY,
        salt=BRANCH_SALT,
        person=BRANCH_PERSON,
        digest_size=BRANCH_DIGEST_SIZE,
    )
    nacl.bindings.crypto_generichash_blake2b_update(finalized, BRANCH_HEADER)
    nacl.bindings.crypto_generichash_blake2b_final(finalized)
    nacl.bindings.crypto_generichash_blake2b_update(finalized, b"more data")
    with pytest.raises(exc.RuntimeError, match="Unexpected failure"):
        nacl.bindings.crypto_generichash_blake2b_final(finalized)
