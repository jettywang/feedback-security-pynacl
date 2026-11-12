Secret Stream Encryption
========================

.. currentmodule:: nacl.secretstream

The :mod:`nacl.secretstream` module wraps the libsodium
``crypto_secretstream_xchacha20poly1305`` construction in two stateful,
strictly separated stream objects. It is intended for archives or uploads
that are produced and consumed incrementally: the receiver only treats the
data as a complete, authenticated archive once the stream's ``FINAL``
record has been verified.

A stream that ends early (a truncated upload, a dropped connection) can
therefore never be mistaken for a success: :attr:`SecretStreamReader.is_complete`
stays ``False`` and :meth:`SecretStreamReader.end_input` raises
:class:`SecretStreamTruncatedError`.

Wire format
-----------

The on-wire stream keeps the plain libsodium construction and adds one thin
record frame:

1. The libsodium secretstream header, written verbatim by the writer.
2. Zero or more records, each made of a 4 byte little-endian length prefix
   followed by exactly that many bytes of unmodified libsodium
   ``crypto_secretstream_xchacha20poly1305_push`` ciphertext.

The length prefix only delimits records; every record body is still
authenticated end to end by libsodium, and a raw libsodium consumer can pull
the framed records directly.

Encrypting an upload
--------------------

.. testcode::

    import nacl.secretstream
    import nacl.utils

    key = nacl.utils.random(nacl.secretstream.KEY_SIZE)

    writer = nacl.secretstream.SecretStreamWriter(key)
    wire = bytearray(writer.header)      # transmit the header first
    wire += writer.write(b"first chunk of the archive")
    writer.rekey()                        # optional explicit re-key
    wire += writer.write(b"second chunk of the archive")
    wire += writer.finalize()             # emits the authenticated FINAL

Decrypting a download
---------------------

Ciphertext may be fed in arbitrarily sized pieces, including one byte at a
time. Plaintext already decrypted from fully authenticated records is
returned immediately, but the archive is only declared complete after the
``FINAL`` record authenticates.

.. testcode::

    reader = nacl.secretstream.SecretStreamReader(key)

    plaintext = bytearray()
    for start in range(0, len(wire), 16):
        plaintext += reader.feed(wire[start:start + 16])

    reader.end_input()                           # confirms the archive end
    plaintext += reader.read()
    assert reader.is_complete

Handling a truncated upload
---------------------------

If the connection closes before the ``FINAL`` record arrives,
:meth:`~SecretStreamReader.end_input` raises and the reader is poisoned: every
further call raises :class:`SecretStreamStateError`, so the object must be
discarded and a fresh reader created.

.. testcode::

    truncated = nacl.secretstream.SecretStreamReader(key)
    truncated.feed(bytes(wire[:-5]))

.. testcode::

    try:
        truncated.end_input()
    except nacl.secretstream.SecretStreamTruncatedError:
        pass  # the upload was incomplete and must not be accepted

    assert truncated.is_complete is False
    assert truncated.is_failed is True

Explicit re-keying
------------------

:meth:`SecretStreamWriter.rekey` marks the next record with the libsodium
``REKEY`` tag. A matching reader rotates its state automatically while
authenticating that record, so forward secrecy is explicit on the wire without
any extra handshake.

Reference
---------

.. autoclass:: SecretStreamWriter(key, chunk_size=DEFAULT_CHUNK_SIZE)
   :members:

.. autoclass:: SecretStreamReader(key, chunk_size=DEFAULT_CHUNK_SIZE)
   :members:

.. autoclass:: SecretStreamError
.. autoclass:: SecretStreamStateError
.. autoclass:: SecretStreamAuthenticationError
.. autoclass:: SecretStreamTruncatedError
.. autoclass:: SecretStreamTrailingDataError
