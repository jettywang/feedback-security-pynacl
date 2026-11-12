# Copyright 2013 Donald Stufft and individual contributors
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

from enum import Enum
from typing import TYPE_CHECKING, ClassVar, Generic, NamedTuple, TypeVar

import nacl.bindings
from nacl import encoding
from nacl import exceptions as exc
from nacl.encoding import Encoder
from nacl.utils import EncryptedMessage, StringFixer, random

if TYPE_CHECKING:
    from typing_extensions import Self


class SessionRole(str, Enum):
    """
    The role used by one side when deriving :class:`SessionKeys`.

    Exactly one side of an exchange must use :attr:`CLIENT`; the other side
    must use :attr:`SERVER`.
    """

    CLIENT = "client"
    SERVER = "server"


class PublicKey(encoding.Encodable, StringFixer):
    """
    The public key counterpart to an Curve25519 :class:`nacl.public.PrivateKey`
    for encrypting messages.

    :param public_key: [:class:`bytes`] Encoded Curve25519 public key
    :param encoder: A class that is able to decode the `public_key`

    :cvar SIZE: The size that the public key is required to be
    """

    SIZE: ClassVar[int] = nacl.bindings.crypto_box_PUBLICKEYBYTES

    def __init__(
        self,
        public_key: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        self._public_key = encoder.decode(public_key)
        if not isinstance(self._public_key, bytes):
            raise exc.TypeError("PublicKey must be created from 32 bytes")

        if len(self._public_key) != self.SIZE:
            raise exc.ValueError(
                f"The public key must be exactly {self.SIZE} bytes long"
            )

    def __bytes__(self) -> bytes:
        return self._public_key

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return nacl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other: object) -> bool:
        return not (self == other)


class PrivateKey(encoding.Encodable, StringFixer):
    """
    Private key for decrypting messages using the Curve25519 algorithm.

    .. warning:: This **must** be protected and remain secret. Anyone who
        knows the value of your :class:`~nacl.public.PrivateKey` can decrypt
        any message encrypted by the corresponding
        :class:`~nacl.public.PublicKey`

    :param private_key: The private key used to decrypt messages
    :param encoder: The encoder class used to decode the given keys

    :cvar SIZE: The size that the private key is required to be
    :cvar SEED_SIZE: The size that the seed used to generate the
                     private key is required to be
    """

    SIZE: ClassVar[int] = nacl.bindings.crypto_box_SECRETKEYBYTES
    SEED_SIZE: ClassVar[int] = nacl.bindings.crypto_box_SEEDBYTES

    def __init__(
        self,
        private_key: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        # Decode the secret_key
        private_key = encoder.decode(private_key)
        # verify the given secret key type and size are correct
        if not (
            isinstance(private_key, bytes) and len(private_key) == self.SIZE
        ):
            raise exc.TypeError(
                f"PrivateKey must be created from a {self.SIZE} bytes long raw secret key"
            )

        raw_public_key = nacl.bindings.crypto_scalarmult_base(private_key)

        self._private_key = private_key
        self.public_key = PublicKey(raw_public_key)

    @classmethod
    def from_seed(
        cls,
        seed: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> PrivateKey:
        """
        Generate a PrivateKey using a deterministic construction
        starting from a caller-provided seed

        .. warning:: The seed **must** be high-entropy; therefore,
            its generator **must** be a cryptographic quality
            random function like, for example, :func:`~nacl.utils.random`.

        .. warning:: The seed **must** be protected and remain secret.
            Anyone who knows the seed is really in possession of
            the corresponding PrivateKey.

        :param seed: The seed used to generate the private key
        :rtype: :class:`~nacl.public.PrivateKey`
        """
        # decode the seed
        seed = encoder.decode(seed)
        # Verify the given seed type and size are correct
        if not (isinstance(seed, bytes) and len(seed) == cls.SEED_SIZE):
            raise exc.TypeError(
                f"PrivateKey seed must be a {cls.SEED_SIZE} bytes long binary sequence"
            )
        # generate a raw key pair from the given seed
        _raw_pk, raw_sk = nacl.bindings.crypto_box_seed_keypair(seed)
        # construct a instance from the raw secret key
        return cls(raw_sk)

    def __bytes__(self) -> bytes:
        return self._private_key

    def __hash__(self) -> int:
        return hash((type(self), bytes(self.public_key)))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return self.public_key == other.public_key

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    @classmethod
    def generate(cls) -> PrivateKey:
        """
        Generates a random :class:`~nacl.public.PrivateKey` object

        :rtype: :class:`~nacl.public.PrivateKey`
        """
        return cls(random(PrivateKey.SIZE), encoder=encoding.RawEncoder)


class SessionKeys(NamedTuple):
    """
    A pair of symmetric keys with explicit directions.

    Use :attr:`send` for messages sent to the peer and :attr:`receive` for
    messages received from the peer. The key bytes are equivalent to the
    ``tx`` and ``rx`` bytes returned by the lower level
    :func:`nacl.bindings.crypto_kx_client_session_keys` and
    :func:`nacl.bindings.crypto_kx_server_session_keys` functions.
    """

    send: bytes
    receive: bytes

    @classmethod
    def derive(
        cls,
        own_keypair: (
            PrivateKey | tuple[PublicKey, PrivateKey] | tuple[bytes, bytes]
        ),
        peer_public_key: PublicKey | bytes,
        role: SessionRole | str,
    ) -> SessionKeys:
        """
        Derive a new :class:`SessionKeys` instance.
        """
        return derive_session_keys(own_keypair, peer_public_key, role)

    @property
    def send_key(self) -> bytes:
        return self.send

    @property
    def receive_key(self) -> bytes:
        return self.receive

    @property
    def tx(self) -> bytes:
        return self.send

    @property
    def rx(self) -> bytes:
        return self.receive


class Box(encoding.Encodable, StringFixer):
    """
    The Box class boxes and unboxes messages between a pair of keys

    The ciphertexts generated by :class:`~nacl.public.Box` include a 16
    byte authenticator which is checked as part of the decryption. An invalid
    authenticator will cause the decrypt function to raise an exception. The
    authenticator is not a signature. Once you've decrypted the message you've
    demonstrated the ability to create arbitrary valid message, so messages you
    send are repudiable. For non-repudiable messages, sign them after
    encryption.

    :param private_key: :class:`~nacl.public.PrivateKey` used to encrypt and
        decrypt messages
    :param public_key: :class:`~nacl.public.PublicKey` used to encrypt and
        decrypt messages

    :cvar NONCE_SIZE: The size that the nonce is required to be.
    """

    NONCE_SIZE: ClassVar[int] = nacl.bindings.crypto_box_NONCEBYTES
    _shared_key: bytes

    def __init__(self, private_key: PrivateKey, public_key: PublicKey):
        if not isinstance(private_key, PrivateKey) or not isinstance(
            public_key, PublicKey
        ):
            raise exc.TypeError(
                "Box must be created from a PrivateKey and a PublicKey"
            )
        self._shared_key = nacl.bindings.crypto_box_beforenm(
            public_key.encode(encoder=encoding.RawEncoder),
            private_key.encode(encoder=encoding.RawEncoder),
        )

    def __bytes__(self) -> bytes:
        return self._shared_key

    @classmethod
    def decode(
        cls, encoded: bytes, encoder: Encoder = encoding.RawEncoder
    ) -> Self:
        """
        Alternative constructor. Creates a Box from an existing Box's shared key.
        """
        # Create an empty box
        box: Self = cls.__new__(cls)

        # Assign our decoded value to the shared key of the box
        box._shared_key = encoder.decode(encoded)

        return box

    def encrypt(
        self,
        plaintext: bytes,
        nonce: bytes | None = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> EncryptedMessage:
        """
        Encrypts the plaintext message using the given `nonce` (or generates
        one randomly if omitted) and returns the ciphertext encoded with the
        encoder.

        .. warning:: It is **VITALLY** important that the nonce is a nonce,
            i.e. it is a number used only once for any given key. If you fail
            to do this, you compromise the privacy of the messages encrypted.

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param nonce: [:class:`bytes`] The nonce to use in the encryption
        :param encoder: The encoder to use to encode the ciphertext
        :rtype: [:class:`nacl.utils.EncryptedMessage`]
        """
        if nonce is None:
            nonce = random(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError(
                f"The nonce must be exactly {self.NONCE_SIZE} bytes long"
            )

        ciphertext = nacl.bindings.crypto_box_easy_afternm(
            plaintext,
            nonce,
            self._shared_key,
        )

        encoded_nonce = encoder.encode(nonce)
        encoded_ciphertext = encoder.encode(ciphertext)

        return EncryptedMessage._from_parts(
            encoded_nonce,
            encoded_ciphertext,
            encoder.encode(nonce + ciphertext),
        )

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes | None = None,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param nonce: [:class:`bytes`] The nonce used when encrypting the
            ciphertext
        :param encoder: The encoder used to decode the ciphertext.
        :rtype: [:class:`bytes`]
        """
        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            # If we were given the nonce and ciphertext combined, split them.
            nonce = ciphertext[: self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE :]

        if len(nonce) != self.NONCE_SIZE:
            raise exc.ValueError(
                f"The nonce must be exactly {self.NONCE_SIZE} bytes long"
            )

        plaintext = nacl.bindings.crypto_box_open_easy_afternm(
            ciphertext,
            nonce,
            self._shared_key,
        )

        return plaintext

    def shared_key(self) -> bytes:
        """
        Returns the Curve25519 shared secret, that can then be used as a key in
        other symmetric ciphers.

        .. warning:: It is **VITALLY** important that you use a nonce with your
            symmetric cipher. If you fail to do this, you compromise the
            privacy of the messages encrypted. Ensure that the key length of
            your cipher is 32 bytes.
        :rtype: [:class:`bytes`]
        """

        return self._shared_key


_Key = TypeVar("_Key", PublicKey, PrivateKey)


class SealedBox(encoding.Encodable, StringFixer, Generic[_Key]):
    """
    The SealedBox class boxes and unboxes messages addressed to
    a specified key-pair by using ephemeral sender's key pairs,
    whose private part will be discarded just after encrypting
    a single plaintext message.

    The ciphertexts generated by :class:`~nacl.public.SecretBox` include
    the public part of the ephemeral key before the :class:`~nacl.public.Box`
    ciphertext.

    :param recipient_key: a :class:`~nacl.public.PublicKey` used to encrypt
        messages and derive nonces, or a :class:`~nacl.public.PrivateKey` used
        to decrypt messages.

    .. versionadded:: 1.2
    """

    _public_key: bytes
    _private_key: bytes | None

    def __init__(self, recipient_key: _Key):
        if isinstance(recipient_key, PublicKey):
            self._public_key = recipient_key.encode(
                encoder=encoding.RawEncoder
            )
            self._private_key = None
        elif isinstance(recipient_key, PrivateKey):
            self._private_key = recipient_key.encode(
                encoder=encoding.RawEncoder
            )
            self._public_key = recipient_key.public_key.encode(
                encoder=encoding.RawEncoder
            )
        else:
            raise exc.TypeError(
                "SealedBox must be created from a PublicKey or a PrivateKey"
            )

    def __bytes__(self) -> bytes:
        return self._public_key

    def encrypt(
        self,
        plaintext: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Encrypts the plaintext message using a random-generated ephemeral
        key pair and returns a "composed ciphertext", containing both
        the public part of the key pair and the ciphertext proper,
        encoded with the encoder.

        The private part of the ephemeral key-pair will be scrubbed before
        returning the ciphertext, therefore, the sender will not be able to
        decrypt the generated ciphertext.

        :param plaintext: [:class:`bytes`] The plaintext message to encrypt
        :param encoder: The encoder to use to encode the ciphertext
        :return bytes: encoded ciphertext
        """

        ciphertext = nacl.bindings.crypto_box_seal(plaintext, self._public_key)

        encoded_ciphertext = encoder.encode(ciphertext)

        return encoded_ciphertext

    def decrypt(
        self: SealedBox[PrivateKey],
        ciphertext: bytes,
        encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        """
        Decrypts the ciphertext using the ephemeral public key enclosed
        in the ciphertext and the SealedBox private key, returning
        the plaintext message.

        :param ciphertext: [:class:`bytes`] The encrypted message to decrypt
        :param encoder: The encoder used to decode the ciphertext.
        :return bytes: The original plaintext
        :raises TypeError: if this SealedBox was created with a
            :class:`~nacl.public.PublicKey` rather than a
            :class:`~nacl.public.PrivateKey`.
        """
        # Decode our ciphertext
        ciphertext = encoder.decode(ciphertext)

        if self._private_key is None:
            raise TypeError(
                "SealedBoxes created with a public key cannot decrypt"
            )
        plaintext = nacl.bindings.crypto_box_seal_open(
            ciphertext,
            self._public_key,
            self._private_key,
        )

        return plaintext


def _coerce_session_role(role: SessionRole | str) -> SessionRole:
    if isinstance(role, SessionRole):
        return role
    if isinstance(role, str):
        try:
            return SessionRole(role)
        except ValueError:
            raise exc.ValueError(
                "role must be 'client' or 'server'"
            ) from None
    raise exc.TypeError(
        "role must be SessionRole.CLIENT or SessionRole.SERVER"
    )


def _local_key_pair_bytes(
    own_keypair: (
        PrivateKey | tuple[PublicKey, PrivateKey] | tuple[bytes, bytes]
    ),
) -> tuple[bytes, bytes]:
    if isinstance(own_keypair, PrivateKey):
        return (
            own_keypair.public_key.encode(encoder=encoding.RawEncoder),
            own_keypair.encode(encoder=encoding.RawEncoder),
        )

    if isinstance(own_keypair, (tuple, list)) and len(own_keypair) == 2:
        first_key, second_key = own_keypair
        if isinstance(first_key, PrivateKey) and isinstance(
            second_key, PublicKey
        ):
            return (
                second_key.encode(encoder=encoding.RawEncoder),
                first_key.encode(encoder=encoding.RawEncoder),
            )
        if isinstance(first_key, PublicKey) and isinstance(
            second_key, PrivateKey
        ):
            return (
                first_key.encode(encoder=encoding.RawEncoder),
                second_key.encode(encoder=encoding.RawEncoder),
            )
        if isinstance(first_key, bytes) and isinstance(second_key, bytes):
            return first_key, second_key

    raise exc.TypeError(
        "own_keypair must be a PrivateKey or a "
        "(PublicKey, PrivateKey) key pair"
    )


def _peer_public_key_bytes(
    peer_public_key: PublicKey | bytes,
) -> bytes:
    if isinstance(peer_public_key, PublicKey):
        return peer_public_key.encode(encoder=encoding.RawEncoder)
    if isinstance(peer_public_key, bytes):
        return peer_public_key
    raise exc.TypeError(
        "peer_public_key must be a PublicKey instance or raw bytes"
    )


def derive_session_keys(
    own_keypair: (
        PrivateKey | tuple[PublicKey, PrivateKey] | tuple[bytes, bytes]
    ),
    peer_public_key: PublicKey | bytes,
    role: SessionRole | str,
) -> SessionKeys:
    """
    Derive directional session keys for one side of a key exchange.

    The peer public key must already have been authenticated through a
    trusted out-of-band channel. This function does not prove that the peer
    holds the matching private key.

    :param own_keypair: the local :class:`PrivateKey`, which carries the
        local public key, or a key pair containing the matching
        :class:`PublicKey` and :class:`PrivateKey`
    :param peer_public_key: the already authenticated peer's
        :class:`PublicKey`
    :param role: :data:`SessionRole.CLIENT` or
        :data:`SessionRole.SERVER` (the strings ``"client"`` and
        ``"server"`` are also accepted)
    :return: a :class:`SessionKeys` value whose ``send`` key encrypts
        outgoing messages and whose ``receive`` key decrypts incoming
        messages
    :raises TypeError: if an argument has an unsupported type
    :raises ValueError: if the role is unknown, the local public and
        private keys do not match, or a key has the wrong length
    """
    session_role = _coerce_session_role(role)
    local_public_key, local_secret_key = _local_key_pair_bytes(own_keypair)
    peer_key = _peer_public_key_bytes(peer_public_key)

    keys = nacl.bindings.crypto_kx_session_keys(
        local_public_key,
        local_secret_key,
        peer_key,
        session_role.value,
    )
    return SessionKeys(send=keys.send, receive=keys.receive)


session_keys = derive_session_keys
