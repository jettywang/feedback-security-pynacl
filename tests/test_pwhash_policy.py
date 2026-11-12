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

from unittest import mock

import pytest

import nacl.bindings
import nacl.exceptions as exc
import nacl.pwhash
from nacl.pwhash import (
    Argon2ResourcePolicy,
    parse_argon2_hash,
)

# tiny, real hashes generated with the lowest cost libsodium accepts
ARGON2ID_HASH = nacl.pwhash.argon2id.str(
    b"correct horse", opslimit=1, memlimit=8192
)
ARGON2I_HASH = nacl.pwhash.argon2i.str(
    b"correct horse", opslimit=3, memlimit=8192
)

# bounds which comfortably accept the low cost hashes above
MEM_BOUND = 64 * 1024 * 1024
OPS_BOUND = 4
POLICY = Argon2ResourcePolicy(max_memlimit=MEM_BOUND, max_opslimit=OPS_BOUND)


def _rebuild(hash_str: bytes, **fields: bytes) -> bytes:
    parts = hash_str.split(b"$")
    parameters = {
        key: value
        for key, value in (item.split(b"=") for item in parts[3].split(b","))
    }
    parameters.update(
        {key.encode("ascii"): value for key, value in fields.items()}
    )
    parts[3] = b",".join(
        b"=".join((key, value)) for key, value in parameters.items()
    )
    return b"$".join(parts)


def test_parse_argon2id_hash_parameters():
    parameters = parse_argon2_hash(ARGON2ID_HASH)
    assert parameters.algorithm == b"argon2id"
    assert parameters.version == 19
    assert parameters.memlimit_kib == 8
    assert parameters.memlimit == 8 * 1024
    assert parameters.opslimit == 1
    assert parameters.lanes == 1


def test_parse_argon2i_hash_parameters():
    parameters = parse_argon2_hash(ARGON2I_HASH)
    assert parameters.algorithm == b"argon2i"
    assert parameters.opslimit == 3
    assert parameters.memlimit_kib == 8
    assert parameters.lanes == 1


def test_policy_accepts_real_argon2_hashes_on_success_path():
    assert (
        nacl.pwhash.verify(ARGON2ID_HASH, b"correct horse", policy=POLICY)
        is True
    )
    assert (
        nacl.pwhash.verify(ARGON2I_HASH, b"correct horse", policy=POLICY)
        is True
    )


def test_policy_still_raises_invalidkey_on_password_mismatch():
    # a password mismatch must remain distinguishable from a policy reject
    with mock.patch.object(
        nacl.bindings,
        "crypto_pwhash_str_verify",
        wraps=nacl.bindings.crypto_pwhash_str_verify,
    ) as native:
        with pytest.raises(exc.InvalidkeyError):
            nacl.pwhash.verify(ARGON2ID_HASH, b"wrong horse", policy=POLICY)
        assert native.call_count == 1


def test_policy_rejects_memory_over_bound_without_computing():
    oversized = _rebuild(ARGON2ID_HASH, m=b"131072")
    with mock.patch.object(
        nacl.bindings,
        "crypto_pwhash_str_verify",
        side_effect=AssertionError("native verify must not be called"),
    ) as native:
        with pytest.raises(exc.PasswordHashPolicyError):
            nacl.pwhash.verify(oversized, b"correct horse", policy=POLICY)
        assert native.call_count == 0


def test_policy_rejects_iterations_over_bound_without_computing():
    oversized = _rebuild(ARGON2ID_HASH, t=b"5")
    with mock.patch.object(
        nacl.bindings,
        "crypto_pwhash_str_verify",
        side_effect=AssertionError("native verify must not be called"),
    ) as native:
        with pytest.raises(exc.PasswordHashPolicyError):
            nacl.pwhash.verify(oversized, b"correct horse", policy=POLICY)
        assert native.call_count == 0


def test_policy_rejects_lanes_over_bound_without_computing():
    policy = Argon2ResourcePolicy(
        max_memlimit=MEM_BOUND, max_opslimit=OPS_BOUND, max_lanes=1
    )
    oversized = _rebuild(ARGON2ID_HASH, p=b"2")
    with mock.patch.object(
        nacl.bindings,
        "crypto_pwhash_str_verify",
        side_effect=AssertionError("native verify must not be called"),
    ) as native:
        with pytest.raises(exc.PasswordHashPolicyError):
            nacl.pwhash.verify(oversized, b"correct horse", policy=policy)
        assert native.call_count == 0


def test_boundary_value_is_accepted():
    # 64 MiB and 4 iterations are exactly the policy bounds
    boundary = _rebuild(
        ARGON2ID_HASH, m=str(MEM_BOUND // 1024).encode("ascii"), t=b"4"
    )
    parameters = parse_argon2_hash(boundary)
    assert parameters.memlimit == MEM_BOUND
    assert parameters.opslimit == OPS_BOUND
    assert POLICY.check(boundary) == parameters


@pytest.mark.parametrize(
    "malformed",
    [
        b"$argon2id$v=19$t=1,p=1$c2FsdA$ZGlnZXN0",  # missing m
        b"$argon2id$v=19$m=8,p=1$c2FsdA$ZGlnZXN0",  # missing t
        b"$argon2id$v=19$m=8,t=1$c2FsdA$ZGlnZXN0",  # missing p
        b"$argon2id$v=19$m=8,m=9,t=1,p=1$c2FsdA$ZGlnZXN0",  # duplicate m
        b"$argon2id$v=19$m=8,t=1,p=1,p=2$c2FsdA$ZGlnZXN0",  # duplicate p
        b"$argon2id$v=19$m=abc,t=1,p=1$c2FsdA$ZGlnZXN0",  # non numeric m
        b"$argon2id$v=19$m=8,t=x,p=1$c2FsdA$ZGlnZXN0",  # non numeric t
        b"$argon2id$v=19$m=8,t=1,p=$c2FsdA$ZGlnZXN0",  # empty p
        b"$argon2id$v=19$m=4294967296,t=1,p=1$c2FsdA$ZGlnZXN0",  # huge m
        b"$argon2id$v=19$m=8,t=0,p=1$c2FsdA$ZGlnZXN0",  # zero t
        b"$argon2id$v=19$m=8,t=1,p=16777216$c2FsdA$ZGlnZXN0",  # huge p
        b"$argon2id$v=19$m=8,t=1,p=1,z=1$c2FsdA$ZGlnZXN0",  # unknown key
        b"$argon2id$v=19$m=8,t=1,p=1$$ZGlnZXN0",  # empty salt
        b"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$",  # empty digest
        b"$argon2id$v=19$m=8,t=1,p=1$c2FsdA",  # missing digest section
        b"$argon2id$v=x$m=8,t=1,p=1$c2FsdA$ZGlnZXN0",  # bad version
        b"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$ZGlnZXN0$extra",  # extra field
    ],
)
def test_malformed_hash_raises_value_error_without_computing(malformed):
    with mock.patch.object(
        nacl.bindings,
        "crypto_pwhash_str_verify",
        side_effect=AssertionError("native verify must not be called"),
    ) as native:
        with pytest.raises(exc.ValueError):
            nacl.pwhash.verify(malformed, b"correct horse", policy=POLICY)
        assert native.call_count == 0


@pytest.mark.parametrize(
    "malformed",
    [
        b"argon2id$v=19$m=8,t=1,p=1$c2FsdA$ZGlnZXN0",  # no leading $
        b"",  # empty
    ],
)
def test_malformed_hash_raises_value_error_at_parser(malformed):
    with pytest.raises(exc.ValueError):
        parse_argon2_hash(malformed)


def test_non_argon_prefix_is_rejected_before_policy_parsing():
    with mock.patch.object(
        nacl.pwhash._policy,
        "parse_argon2_hash",
        side_effect=AssertionError("parser must not run on foreign prefix"),
    ):
        with pytest.raises(exc.CryptPrefixError):
            nacl.pwhash.verify(
                b"argon2id$v=19$m=8,t=1,p=1$x$y",
                b"correct horse",
                policy=POLICY,
            )


def test_unsupported_algorithm_raises_prefix_error_without_computing():
    unsupported = b"$argon2d$v=19$m=8,t=1,p=1$c2FsdA$ZGlnZXN0"
    with mock.patch.object(
        nacl.bindings,
        "crypto_pwhash_str_verify",
        side_effect=AssertionError("native verify must not be called"),
    ) as native:
        with pytest.raises(exc.CryptPrefixError):
            nacl.pwhash.verify(unsupported, b"correct horse", policy=POLICY)
        assert native.call_count == 0


def test_policy_reject_is_distinct_from_value_and_invalidkey_errors():
    oversized = _rebuild(ARGON2ID_HASH, m=b"131072")
    assert not issubclass(exc.PasswordHashPolicyError, exc.InvalidkeyError)
    assert not issubclass(exc.PasswordHashPolicyError, exc.ValueError)
    with pytest.raises(exc.PasswordHashPolicyError):
        POLICY.check(oversized)


def test_legacy_verify_without_policy_is_unchanged():
    # no policy: parser must not run at all, behavior is the historical one
    with mock.patch.object(
        nacl.pwhash._policy,
        "parse_argon2_hash",
        side_effect=AssertionError("parser must not run without a policy"),
    ):
        assert nacl.pwhash.verify(ARGON2ID_HASH, b"correct horse") is True
        with pytest.raises(exc.InvalidkeyError):
            nacl.pwhash.verify(ARGON2ID_HASH, b"wrong horse")


def test_legacy_verify_never_invokes_the_policy():
    oversized = _rebuild(ARGON2ID_HASH, m=b"131072")
    # without a policy the oversized parameters are not inspected; the hash
    # is handed straight to libsodium which reports a plain password mismatch
    with mock.patch.object(
        nacl.pwhash._policy,
        "Argon2ResourcePolicy",
        side_effect=AssertionError("policy machinery must not run"),
    ):
        with pytest.raises(exc.InvalidkeyError):
            nacl.pwhash.verify(oversized, b"correct horse")


def test_policy_check_returns_parsed_parameters():
    parameters = parse_argon2_hash(ARGON2ID_HASH)
    assert POLICY.check(ARGON2ID_HASH) == parameters


def test_policy_constructor_validates_its_own_bounds():
    with pytest.raises(exc.ValueError):
        Argon2ResourcePolicy(max_memlimit=0, max_opslimit=4)
    with pytest.raises(exc.ValueError):
        Argon2ResourcePolicy(max_memlimit=64, max_opslimit=0)
    with pytest.raises(exc.ValueError):
        Argon2ResourcePolicy(max_memlimit=64, max_opslimit=4, max_lanes=0)
    with pytest.raises(exc.TypeError):
        Argon2ResourcePolicy(max_memlimit="64", max_opslimit=4)  # type: ignore[arg-type]
    with pytest.raises(exc.TypeError):
        Argon2ResourcePolicy(max_memlimit=True, max_opslimit=4)


def test_parse_rejects_non_bytes():
    with pytest.raises(exc.TypeError):
        parse_argon2_hash("$argon2id$v=19$m=8,t=1,p=1$x$y")  # type: ignore[arg-type]


def test_parse_accepts_legacy_versionless_encoding():
    parameters = parse_argon2_hash(b"$argon2id$m=8,t=1,p=1$c2FsdA$ZGlnZXN0")
    assert parameters.version == 0x10
    assert parameters.algorithm == b"argon2id"


def test_parse_rejects_unicode_digits_and_negative_numbers():
    # U+0661 ARABIC-INDIC DIGIT ONE must not be accepted as an ASCII digit
    with pytest.raises(exc.ValueError):
        parse_argon2_hash("$argon2id$v=19$m=١,t=1,p=1$x$y".encode("utf-8"))
    with pytest.raises(exc.ValueError):
        parse_argon2_hash(b"$argon2id$v=-1$m=8,t=1,p=1$x$y")
