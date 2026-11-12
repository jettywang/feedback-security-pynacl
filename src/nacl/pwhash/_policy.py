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

"""
Optional, parser-only resource policy for Argon2 password hashes.

Imported partner hashes are passed verbatim to libsodium by the
``verify`` helpers. This module makes it possible to inspect the cost
parameters encoded in an Argon2 modular-crypt string and reject hashes
which would request more memory or iterations than the service is willing
to spend, *before* any password hashing computation is started.
"""

from __future__ import annotations

from dataclasses import dataclass

import nacl.bindings
import nacl.exceptions as exc

#: algorithm name as encoded in the modular crypt string -> binding alg id
_ARGON2_ALGORITHMS = {
    b"argon2i": nacl.bindings.crypto_pwhash_ALG_ARGON2I13,
    b"argon2id": nacl.bindings.crypto_pwhash_ALG_ARGON2ID13,
}

#: cost parameters which are required exactly once in the parameter section
_REQUIRED_COST_KEYS = (b"m", b"t", b"p")

#: Argon2 modular crypt strings use the unpadded standard base64 alphabet
_B64_ALPHABET = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" b"abcdefghijklmnopqrstuvwxyz" b"0123456789+/"
)

#: libsodium only accepts a 24 bit parallelism factor
_MAX_LANES = (1 << 24) - 1

#: a 32 bit unsigned integer is the largest cost value libsodium understands
_MAX_UINT32 = (1 << 32) - 1


@dataclass(frozen=True)
class Argon2Parameters:
    """The parameters parsed from an Argon2 modular crypt hash string."""

    algorithm: bytes
    version: int
    memlimit_kib: int
    opslimit: int
    lanes: int

    @property
    def alg_id(self) -> int:
        """The libsodium algorithm identifier for :attr:`algorithm`."""
        return _ARGON2_ALGORITHMS[self.algorithm]

    @property
    def memlimit(self) -> int:
        """The requested memory occupation, in bytes."""
        return self.memlimit_kib * 1024


def _parse_decimal(name: bytes, raw: bytes) -> int:
    # str.isdigit accepts unicode digits and an empty string is False, so
    # match the ASCII [0-9]+ grammar explicitly instead of using int() alone.
    if not raw or any(ch < 0x30 or ch > 0x39 for ch in raw):
        raise exc.ValueError(
            f"invalid {name.decode('ascii')} cost parameter in password hash"
        )
    return int(raw)


def _check_b64_section(name: str, section: bytes) -> None:
    if not section or any(ch not in _B64_ALPHABET for ch in section):
        raise exc.ValueError(f"invalid {name} section in password hash")


def parse_argon2_hash(password_hash: bytes) -> Argon2Parameters:
    """
    Parse the cost parameters from an Argon2 modular crypt hash.

    Only the ``argon2i`` and ``argon2id`` encodings produced by libsodium
    are understood. Malformed strings (missing or duplicated fields,
    non-numeric or out of range costs, ...) raise
    :class:`~nacl.exceptions.ValueError`, while a supported prefix carrying
    an unknown algorithm name raises
    :class:`~nacl.exceptions.CryptPrefixError`. No password hashing work is
    performed by this function.

    :param password_hash: the modular crypt encoded password hash
    :type password_hash: bytes
    :rtype: Argon2Parameters
    """
    if not isinstance(password_hash, bytes):
        raise exc.TypeError("password_hash must be bytes")

    parts = password_hash.split(b"$")
    # A modular crypt string starts with '$', so the first split part is
    # always empty. The overall shape is either
    #   $alg$v=N$m=..,t=..,p=..$salt$digest          (6 parts)
    # or the version-less
    #   $alg$m=..,t=..,p=..$salt$digest              (5 parts)
    if (
        parts[0] != b""
        or len(parts) not in (5, 6)
        or any(part == b"" for part in parts[1:])
    ):
        raise exc.ValueError("malformed argon2 password hash")

    algorithm = parts[1]
    if algorithm not in _ARGON2_ALGORITHMS:
        raise exc.CryptPrefixError(
            "unsupported argon2 algorithm in password hash"
        )

    if len(parts) == 6:
        version_section = parts[2]
        parameter_section = parts[3]
        salt = parts[4]
        digest = parts[5]
        if not version_section.startswith(b"v="):
            raise exc.ValueError("malformed argon2 version in password hash")
        version = _parse_decimal(b"v", version_section[2:])
    else:
        parameter_section = parts[2]
        salt = parts[3]
        digest = parts[4]
        # libsodium always writes a version, but treat the legacy encoding
        # as version 0x10 for completeness.
        version = 0x10

    _check_b64_section("salt", salt)
    _check_b64_section("digest", digest)

    costs: dict[bytes, int] = {}
    for item in parameter_section.split(b","):
        key, sep, raw_value = item.partition(b"=")
        if not sep or key not in _REQUIRED_COST_KEYS:
            raise exc.ValueError(
                "malformed argon2 cost parameters in password hash"
            )
        if key in costs:
            raise exc.ValueError(
                f"duplicated {key.decode('ascii')} cost parameter "
                "in password hash"
            )
        costs[key] = _parse_decimal(key, raw_value)

    missing = [key for key in _REQUIRED_COST_KEYS if key not in costs]
    if missing:
        raise exc.ValueError(
            "missing cost parameter(s) in password hash: "
            + ", ".join(key.decode("ascii") for key in missing)
        )

    memlimit_kib = costs[b"m"]
    opslimit = costs[b"t"]
    lanes = costs[b"p"]

    if not 1 <= memlimit_kib <= _MAX_UINT32:
        raise exc.ValueError(
            "memory cost m is outside of the allowed numeric range"
        )
    if not 1 <= opslimit <= _MAX_UINT32:
        raise exc.ValueError(
            "iteration count t is outside of the allowed numeric range"
        )
    if not 1 <= lanes <= _MAX_LANES:
        raise exc.ValueError(
            "parallelism p is outside of the allowed numeric range"
        )

    return Argon2Parameters(
        algorithm=algorithm,
        version=version,
        memlimit_kib=memlimit_kib,
        opslimit=opslimit,
        lanes=lanes,
    )


class Argon2ResourcePolicy:
    """
    Optional resource bounds applied to Argon2 verification requests.

    Instances are immutable and only parse the encoded hash; they never
    trigger a password hashing computation. A hash whose requested memory,
    iteration count or parallelism exceeds the configured bounds raises
    :class:`~nacl.exceptions.PasswordHashPolicyError`.

    :param max_memlimit: maximum accepted memory occupation, in bytes
                         (the modular crypt ``m`` value is expressed in KiB)
    :type max_memlimit: int
    :param max_opslimit: maximum accepted iteration count (the ``t`` value)
    :type max_opslimit: int
    :param max_lanes: maximum accepted parallelism factor (the ``p`` value)
    :type max_lanes: int
    """

    def __init__(
        self,
        max_memlimit: int,
        max_opslimit: int,
        max_lanes: int = _MAX_LANES,
    ) -> None:
        if not isinstance(max_memlimit, int) or isinstance(max_memlimit, bool):
            raise exc.TypeError("max_memlimit must be an integer")
        if not isinstance(max_opslimit, int) or isinstance(max_opslimit, bool):
            raise exc.TypeError("max_opslimit must be an integer")
        if not isinstance(max_lanes, int) or isinstance(max_lanes, bool):
            raise exc.TypeError("max_lanes must be an integer")
        if max_memlimit < 1:
            raise exc.ValueError("max_memlimit must be positive")
        if max_opslimit < 1:
            raise exc.ValueError("max_opslimit must be positive")
        if not 1 <= max_lanes <= _MAX_LANES:
            raise exc.ValueError(
                f"max_lanes must be between 1 and {_MAX_LANES}"
            )

        self._max_memlimit = max_memlimit
        self._max_opslimit = max_opslimit
        self._max_lanes = max_lanes

    @property
    def max_memlimit(self) -> int:
        """The configured memory bound, in bytes."""
        return self._max_memlimit

    @property
    def max_opslimit(self) -> int:
        """The configured iteration bound."""
        return self._max_opslimit

    @property
    def max_lanes(self) -> int:
        """The configured parallelism bound."""
        return self._max_lanes

    def check(self, password_hash: bytes) -> Argon2Parameters:
        """
        Parse ``password_hash`` and enforce the configured resource bounds.

        :param password_hash: the modular crypt encoded argon2 password hash
        :type password_hash: bytes
        :return: the parsed parameters when the hash is accepted
        :rtype: Argon2Parameters
        :raises nacl.exceptions.PasswordHashPolicyError: if a cost parameter
            exceeds the policy bounds. The exception is raised before any
            password hashing computation is started.
        """
        parameters = parse_argon2_hash(password_hash)

        if parameters.memlimit > self._max_memlimit:
            raise exc.PasswordHashPolicyError(
                f"password hash requests {parameters.memlimit} bytes of "
                f"memory, policy limit is {self._max_memlimit} bytes"
            )
        if parameters.opslimit > self._max_opslimit:
            raise exc.PasswordHashPolicyError(
                f"password hash requests {parameters.opslimit} iterations, "
                f"policy limit is {self._max_opslimit}"
            )
        if parameters.lanes > self._max_lanes:
            raise exc.PasswordHashPolicyError(
                f"password hash requests {parameters.lanes} lanes, policy "
                f"limit is {self._max_lanes}"
            )

        return parameters
