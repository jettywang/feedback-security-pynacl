# Copyright 2017 Donald Stufft and individual contributors
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

from nacl.exceptions import CryptPrefixError

from . import _argon2, argon2i, argon2id, scrypt
from ._policy import Argon2Parameters as Argon2Parameters
from ._policy import Argon2ResourcePolicy as Argon2ResourcePolicy
from ._policy import parse_argon2_hash as parse_argon2_hash

STRPREFIX = argon2id.STRPREFIX

PWHASH_SIZE = argon2id.PWHASH_SIZE

assert _argon2.ALG_ARGON2_DEFAULT == _argon2.ALG_ARGON2ID13
# since version 1.0.15 of libsodium

PASSWD_MIN = argon2id.PASSWD_MIN
PASSWD_MAX = argon2id.PASSWD_MAX
MEMLIMIT_MAX = argon2id.MEMLIMIT_MAX
MEMLIMIT_MIN = argon2id.MEMLIMIT_MIN
OPSLIMIT_MAX = argon2id.OPSLIMIT_MAX
OPSLIMIT_MIN = argon2id.OPSLIMIT_MIN
OPSLIMIT_INTERACTIVE = argon2id.OPSLIMIT_INTERACTIVE
MEMLIMIT_INTERACTIVE = argon2id.MEMLIMIT_INTERACTIVE
OPSLIMIT_MODERATE = argon2id.OPSLIMIT_MODERATE
MEMLIMIT_MODERATE = argon2id.MEMLIMIT_MODERATE
OPSLIMIT_SENSITIVE = argon2id.OPSLIMIT_SENSITIVE
MEMLIMIT_SENSITIVE = argon2id.MEMLIMIT_SENSITIVE

str = argon2id.str

assert argon2i.ALG != argon2id.ALG

SCRYPT_SALTBYTES = scrypt.SALTBYTES
SCRYPT_PWHASH_SIZE = scrypt.PWHASH_SIZE
SCRYPT_OPSLIMIT_INTERACTIVE = scrypt.OPSLIMIT_INTERACTIVE
SCRYPT_MEMLIMIT_INTERACTIVE = scrypt.MEMLIMIT_INTERACTIVE
SCRYPT_OPSLIMIT_SENSITIVE = scrypt.OPSLIMIT_SENSITIVE
SCRYPT_MEMLIMIT_SENSITIVE = scrypt.MEMLIMIT_SENSITIVE


kdf_scryptsalsa208sha256 = scrypt.kdf
scryptsalsa208sha256_str = scrypt.str
verify_scryptsalsa208sha256 = scrypt.verify


def verify(
    password_hash: bytes,
    password: bytes,
    policy: Argon2ResourcePolicy | None = None,
) -> bool:
    """
    Takes a modular crypt encoded stored password hash derived using one
    of the algorithms supported by `libsodium` and checks if the user provided
    password will hash to the same string when using the parameters saved
    in the stored hash

    When an optional :class:`.Argon2ResourcePolicy` is passed as ``policy``,
    the cost parameters of argon2i and argon2id hashes are parsed and
    checked against the policy's resource bounds *before* any password
    hashing computation is started. A rejected hash raises
    :class:`nacl.exceptions.PasswordHashPolicyError`; malformed hashes raise
    the usual :class:`nacl.exceptions.ValueError` instead, so both cases
    stay distinct from an :class:`nacl.exceptions.InvalidkeyError` raised on
    a password mismatch. When ``policy`` is ``None`` (the default) the
    historical, unchecked behavior is preserved.

    :param password_hash: password hash serialized in modular crypt() format
    :type password_hash: bytes
    :param password: user provided password
    :type password: bytes
    :param policy: optional resource policy enforced on argon2 hashes
    :type policy: Argon2ResourcePolicy or None
    :rtype: boolean
    """
    if password_hash.startswith((argon2id.STRPREFIX, argon2i.STRPREFIX)):
        if policy is not None:
            policy.check(password_hash)
        return argon2id.verify(password_hash, password)
    elif scrypt.AVAILABLE and password_hash.startswith(scrypt.STRPREFIX):
        return scrypt.verify(password_hash, password)
    else:
        raise (
            CryptPrefixError(
                "given password_hash is not in a supported format"
            )
        )
