Utilities
=========

.. currentmodule:: nacl.utils

.. class:: StringFixer

    Mixin which makes ``str(obj)`` (and therefore f-strings and ``%s``
    formatting) equivalent to ``str(bytes(obj))``. It is used by the public
    key classes :class:`~nacl.public.PublicKey` and
    :class:`~nacl.signing.VerifyKey`, whose key material is not secret.

.. class:: SecretStringFixer

    Mixin for classes which hold secret key material:
    :class:`~nacl.public.PrivateKey`, :class:`~nacl.public.Box`,
    :class:`~nacl.public.SealedBox`, :class:`~nacl.secret.SecretBox`,
    :class:`~nacl.secret.Aead` and :class:`~nacl.signing.SigningKey`.

    Rendering such an object never includes the underlying bytes. Every
    rendering channel -- ``str(obj)``, ``repr(obj)``, f-strings,
    ``"%s" % obj`` and logging the object directly or inside a
    ``list``/``tuple``/``dict`` -- produces a fixed placeholder of the form
    ``<module.ClassName [redacted]>``, so neither the raw bytes nor their
    escaped (``\\x..``) or hexadecimal forms can leak into logs.

    To deliberately serialize a secret, use the explicit byte-oriented
    interface instead of string formatting::

        raw = bytes(secret_box)
        as_hex = secret_box.encode(encoder=nacl.encoding.HexEncoder)

    Code which previously relied on ``str(secret)`` returning the bytes must
    migrate to one of those calls.

.. class:: EncryptedMessage

    A ``bytes`` subclass that holds a message that has been encrypted by a
    :class:`~nacl.secret.SecretBox` or :class:`~nacl.public.Box`. The full
    content of the ``bytes`` object is the combined ``nonce`` and
    ``ciphertext``.

    .. attribute:: nonce

        The nonce used during the encryption of the :class:`EncryptedMessage`.

    .. attribute:: ciphertext

        The ciphertext contained within the :class:`EncryptedMessage`.

.. function:: random(size=32)

    Returns a random bytestring with the given ``size``.

    :param bytes size: The size of the random bytestring.
    :return bytes: The random bytestring.

.. function:: randombytes_deterministic(size, seed, encoder=encoding.RawEncoder)

    Returns ``size`` number of deterministically generated pseudorandom bytes
    from a 32 byte seed.

    :param bytes size: The size of the random bytestring.
    :param bytes seed: The seed for the bytestring. This should be 32 bytes
                            or a TypeError will be thrown.
    :param encoder: The encoder class used to encode the produced bytes.
    :return bytes: The random bytestring.

