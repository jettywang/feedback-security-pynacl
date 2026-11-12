Public Key Encryption
=====================

.. currentmodule:: nacl.public

Imagine Alice wants something valuable shipped to her. Because it's valuable,
she wants to make sure it arrives securely (i.e. hasn't been opened or
tampered with) and that it's not a forgery (i.e. it's actually from the sender
she's expecting it to be from and nobody's pulling the old switcheroo).

One way she can do this is by providing the sender (let's call him Bob) with a
high-security box of her choosing. She provides Bob with this box, and
something else: a padlock, but a padlock without a key. Alice is keeping that
key all to herself. Bob can put items in the box then put the padlock onto it.
But once the padlock snaps shut, the box cannot be opened by anyone who
doesn't have Alice's private key.

Here's the twist though: Bob also puts a padlock onto the box. This padlock
uses a key Bob has published to the world, such that if you have one of Bob's
keys, you know a box came from him because Bob's keys will open Bob's padlocks
(let's imagine a world where padlocks cannot be forged even if you know the
key). Bob then sends the box to Alice.

In order for Alice to open the box, she needs two keys: her private key that
opens her own padlock, and Bob's well-known key. If Bob's key doesn't open the
second padlock, then Alice knows that this is not the box she was expecting
from Bob, it's a forgery.

This bidirectional guarantee around identity is known as mutual authentication.


Examples
--------

nacl.public.Box
~~~~~~~~~~~~~~~

The :class:`~nacl.public.Box` class uses the given public and private (secret)
keys to derive a shared key, which is used with the nonce given to encrypt the
given messages and to decrypt the given ciphertexts.  The same shared key will
be generated from both pairing of keys, so given two key pairs belonging to
Alice (pkalice, skalice) and Bob (pkbob, skbob), the key derived from
(pkalice, skbob) will equal that from (pkbob, skalice).

This is how the system works:

.. testcode::

    import nacl.utils
    from nacl.public import PrivateKey, Box

    # Generate Bob's private key, which must be kept secret
    skbob = PrivateKey.generate()

    # Bob's public key can be given to anyone wishing to send
    #   Bob an encrypted message
    pkbob = skbob.public_key

    # Alice does the same and then Alice and Bob exchange public keys
    skalice = PrivateKey.generate()
    pkalice = skalice.public_key

    # Bob wishes to send Alice an encrypted message so Bob must make a Box with
    #   his private key and Alice's public key
    bob_box = Box(skbob, pkalice)

    # This is our message to send, it must be a bytestring as Box will treat it
    #   as just a binary blob of data.
    message = b"Kill all humans"

PyNaCl can automatically generate a random nonce for us, making the encryption
very simple:

.. testcode::

    # Encrypt our message, it will be exactly 40 bytes longer than the
    #   original message as it stores authentication information and the
    #   nonce alongside it.
    encrypted = bob_box.encrypt(message)

However, if we need to use an explicit nonce, it can be passed along with the
message:

.. testcode::

    # This is a nonce, it *MUST* only be used once, but it is not considered
    #   secret and can be transmitted or stored alongside the ciphertext. A
    #   good source of nonces are just sequences of 24 random bytes.
    nonce = nacl.utils.random(Box.NONCE_SIZE)

    encrypted = bob_box.encrypt(message, nonce)

Finally, the message is decrypted (regardless of how the nonce was generated):

.. testcode::

    # Alice creates a second box with her private key to decrypt the message
    alice_box = Box(skalice, pkbob)

    # Decrypt our message, an exception will be raised if the encryption was
    #   tampered with or there was otherwise an error.
    plaintext = alice_box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))

.. testoutput::

    Kill all humans


nacl.public.SealedBox
~~~~~~~~~~~~~~~~~~~~~

The :class:`~nacl.public.SealedBox` class encrypts messages addressed
to a specified key-pair by using ephemeral sender's key pairs, which
will be discarded just after encrypting a single plaintext message.

This kind of construction allows sending messages, which only the recipient
can decrypt without providing any kind of cryptographic proof of sender's
authorship.

.. warning:: By design, the recipient will have no means to trace
    the ciphertext to a known author, since the sending
    key pair itself is not bound to any sender's identity, and
    the sender herself will not be able to decrypt the ciphertext
    she just created, since the private part of the key cannot be
    recovered after use.

This is how the system works:

.. testcode::

    import nacl.utils
    from nacl.public import PrivateKey, SealedBox

    # Generate Bob's private key, as we've done in the Box example
    skbob = PrivateKey.generate()
    pkbob = skbob.public_key

    # Alice wishes to send a encrypted message to Bob,
    # but prefers the message to be untraceable
    sealed_box = SealedBox(pkbob)

    # This is Alice's message
    message = b"Kill all kittens"

    # Encrypt the message, it will carry the ephemeral key public part
    # to let Bob decrypt it
    encrypted = sealed_box.encrypt(message)

Now, Bob wants to read the secret message he just received; therefore
he must create a SealedBox using his own private key:

.. testcode::

    unseal_box = SealedBox(skbob)
    # decrypt the received message
    plaintext = unseal_box.decrypt(encrypted)
    print(plaintext.decode('utf-8'))

.. testoutput::

    Kill all kittens


Session Keys
~~~~~~~~~~~~

:func:`~nacl.public.derive_session_keys` provides a safer interface on top
of the ``crypto_kx`` key-exchange functions. The caller supplies a complete
local key pair, the peer's already authenticated public key, and an explicit
role. The result uses the names :attr:`~nacl.public.SessionKeys.send` and
:attr:`~nacl.public.SessionKeys.receive` instead of an unnamed
``(rx, tx)`` tuple.

.. testcode::

    from nacl.public import (
        PrivateKey,
        SessionRole,
        derive_session_keys,
    )
    from nacl.secret import SecretBox

    client_private_key = PrivateKey.generate()
    server_private_key = PrivateKey.generate()

    client_keys = derive_session_keys(
        client_private_key,
        server_private_key.public_key,
        SessionRole.CLIENT,
    )
    server_keys = derive_session_keys(
        server_private_key,
        client_private_key.public_key,
        SessionRole.SERVER,
    )

    assert client_keys.send == server_keys.receive
    assert client_keys.receive == server_keys.send

    ciphertext = SecretBox(client_keys.send).encrypt(b"session message")
    plaintext = SecretBox(server_keys.receive).decrypt(ciphertext)
    assert plaintext == b"session message"

One side must use :data:`~nacl.public.SessionRole.CLIENT` and the other must
use :data:`~nacl.public.SessionRole.SERVER`. If both sides select the same
role, their keys are not complementary and messages encrypted with
:attr:`~nacl.public.SessionKeys.send` cannot be decrypted with the peer's
:attr:`~nacl.public.SessionKeys.receive`.

The peer public key must be obtained and authenticated before deriving keys.
Use a trusted source such as pinned configuration, a trusted key directory
or certificate, or an out-of-band fingerprint comparison. ``crypto_kx`` does
not authenticate the peer; accepting an unauthenticated public key permits an
active attacker to establish separate session keys with both sides.

The returned keys are normal 32-byte symmetric keys, so they can be used with
:class:`~nacl.secret.SecretBox`, :class:`~nacl.secret.Aead`, or another
32-byte cipher. They are the same bytes produced by the lower level
``crypto_kx_*_session_keys`` functions: ``send`` is the lower level ``tx``
key and ``receive`` is the lower level ``rx`` key.

Derive a fresh pair for each connection or session. Derive again when either
side rotates a key pair, when the authenticated peer public key changes, when
the negotiated role changes, when a configured rekey point is reached, or
when compromise is suspected. Reusing the same long-term key pair produces the
same session keys on every exchange; prefer a per-session ephemeral
:class:`PrivateKey`, or otherwise ensure that every nonce used with the keys
remains unique.


Reference
---------

.. class:: PublicKey(public_key, encoder)

    The public key counterpart to an Curve25519
    :class:`~nacl.public.PrivateKey` for encrypting messages.

    :param bytes public_key: Encoded Curve25519 public key.
    :param encoder: A class that is able to decode the ``public_key``.

.. class:: PrivateKey(private_key, encoder)

    Private key for decrypting messages using the Curve25519 algorithm.

    .. warning:: This **must** be protected and remain secret. Anyone who
        knows the value of your :class:`~nacl.public.PrivateKey` can decrypt
        any message encrypted by the corresponding
        :class:`~nacl.public.PublicKey`

    :param bytes private_key: The private key used to decrypt messages.
    :param encoder: A class that is able to decode the ``private_key``.

    .. attribute:: public_key

        An instance of :class:`~.nacl.public.PublicKey` that corresponds with
        the private key.

    .. classmethod:: generate()

        Generates a random :class:`~nacl.public.PrivateKey` object

        :return: An instance of :class:`~nacl.public.PrivateKey`.

.. class:: SessionRole

    The role used by one side of a key exchange.

    .. attribute:: CLIENT

        The initiator-side role.

    .. attribute:: SERVER

        The responder-side role.

.. class:: SessionKeys(send, receive)

    Symmetric session keys with explicit directions.

    .. attribute:: send

        The 32-byte key used to encrypt messages sent to the peer. This is
        the lower level ``tx`` key.

    .. attribute:: receive

        The 32-byte key used to decrypt messages received from the peer.
        This is the lower level ``rx`` key.

    .. classmethod:: derive(own_keypair, peer_public_key, role)

        Equivalent to calling
        :func:`~nacl.public.derive_session_keys`.

        :return: An instance of :class:`~nacl.public.SessionKeys`.

.. function:: derive_session_keys(own_keypair, peer_public_key, role)

    Derive directional session keys for one side of a key exchange.

    :param own_keypair: A :class:`~nacl.public.PrivateKey` containing the
        local key pair, or a matching
        (:class:`~nacl.public.PublicKey`,
        :class:`~nacl.public.PrivateKey`) pair. Raw key bytes may be passed
        as a ``(public_key, secret_key)`` tuple.
    :param peer_public_key: The peer's already authenticated
        :class:`~nacl.public.PublicKey`, or its 32 raw bytes.
    :param role: :data:`SessionRole.CLIENT` or
        :data:`SessionRole.SERVER`; the strings ``"client"`` and
        ``"server"`` are also accepted.
    :return: A :class:`SessionKeys` instance.
    :raises TypeError: if an argument has an unsupported type or length.
    :raises ValueError: if the role is unknown or the local public and
        private keys do not form a matching pair.

``session_keys`` is available as a shorter alias for
:func:`derive_session_keys`.

.. class:: Box(private_key, public_key)

    The Box class boxes and unboxes messages between a pair of keys

    The ciphertexts generated by :class:`~nacl.public.Box` include a 16
    byte authenticator which is checked as part of the decryption. An invalid
    authenticator will cause the decrypt function to raise an exception. The
    authenticator is not a signature. Once you've decrypted the message you've
    demonstrated the ability to create arbitrary valid message, so messages you
    send are repudiable. For non-repudiable messages, sign them after
    encryption.

    :param private_key: An instance of :class:`~nacl.public.PrivateKey` used
        to encrypt and decrypt messages
    :param public_key: An instance of :class:`~nacl.public.PublicKey` used to
        encrypt and decrypt messages

    .. classmethod:: decode(encoded, encoder)

        Decodes a serialized :class:`~nacl.public.Box`.

        :return: An instance of :class:`~nacl.public.Box`.

    .. method:: encrypt(plaintext, nonce, encoder)

        Encrypts the plaintext message using the given `nonce` (or generates
        one randomly if omitted) and returns the ciphertext encoded with the
        encoder.

        .. warning:: It is **VITALLY** important that the nonce is a nonce,
            i.e. it is a number used only once for any given key. If you
            fail to do this, you compromise the privacy of the messages
            encrypted.

        :param bytes plaintext: The plaintext message to encrypt.
        :param bytes nonce: The nonce to use in the encryption.
        :param encoder:  A class that is able to decode the ciphertext.

        :return: An instance of :class:`~nacl.utils.EncryptedMessage`.

    .. method:: decrypt(ciphertext, nonce, encoder)

        Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
        parameter or implicitly, when omitted, as part of the ciphertext) and
        returns the plaintext message.

        :param bytes ciphertext: The encrypted message to decrypt.
        :param bytes nonce: The nonce to use in the decryption.
        :param encoder: A class that is able to decode the plaintext.

        :return bytes: The decrypted plaintext.

    .. method:: shared_key()

        Returns the Curve25519 shared secret, that can then be used as a key in
        other symmetric ciphers.

        .. warning:: It is **VITALLY** important that you use a nonce with your
            symmetric cipher. If you fail to do this, you compromise the
            privacy of the messages encrypted. Ensure that the key length of
            your cipher is 32 bytes.

        :return bytes: The shared secret.

.. class:: SealedBox(receiver_key)

    The SealedBox class can box and unbox messages sent to a receiver key
    using an ephemeral sending key pair.

    .. method:: encrypt(plaintext, encoder)

        Encrypt the message using a Box constructed from an ephemeral
        key-pair and the receiver key.

        The public part of the ephemeral key-pair will be enclosed in the
        returned ciphertext.

        The private part of the ephemeral key-pair will be scrubbed before
        returning the ciphertext, therefore, the sender will not be able
        to decrypt the message.

        :param bytes plaintext: The plaintext message to encrypt.
        :param encoder:  A class that is able to decode the ciphertext.

        :return bytes: The public part of the ephemeral key pair,
                       followed by the encrypted ciphertext

    .. method:: decrypt(ciphertext, encoder)

        Decrypt the message using a Box constructed from the receiver key
        and the ephemeral key enclosed in the ciphertext.

        :param bytes ciphertext: The ciphertext message to decrypt.
        :param encoder:  A class that is able to decode the ciphertext.

        :return bytes: The decrypted message

Algorithm
~~~~~~~~~

* **Public Keys:** `Curve25519 high-speed elliptic curve cryptography <https://cr.yp.to/ecdh.html>`_
