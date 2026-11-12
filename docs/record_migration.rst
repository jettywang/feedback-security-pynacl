Record Migration
================

.. currentmodule:: nacl.record_migration

The :py:mod:`nacl.record_migration` module migrates persisted
:class:`~nacl.secret.SecretBox` records to versioned
:class:`~nacl.secret.Aead` records.  The new version protects the record's
tenant and purpose as AEAD associated data in addition to its ciphertext.

Legacy read rules
-----------------

There are exactly two legacy layouts.  The layout and encoder are declared
per record; readers never auto-detect a format or retry another parser.

``LegacyLayout.COMBINED``
    The stored payload is the encoded ``EncryptedMessage`` returned by
    :meth:`~nacl.secret.SecretBox.encrypt`.  The encoder was applied once to
    ``nonce + ciphertext``, so the payload is decoded once and then split at
    :attr:`~nacl.secret.SecretBox.NONCE_SIZE`.

``LegacyLayout.SPLIT``
    The nonce and ciphertext are separate fields.  When
    ``nonce_encoded`` is true, both fields came from
    ``EncryptedMessage.nonce`` and ``EncryptedMessage.ciphertext`` and each is
    decoded once.  When it is false, the stored nonce is the raw nonce passed
    to encryption and only the ciphertext is decoded.

Versioned records
-----------------

New records declare ``CURRENT_VERSION`` and store the raw 24-byte XChaCha20
nonce separately from the raw AEAD ciphertext.  The associated data contains
a domain separator, the version, a length-prefixed tenant and a
length-prefixed purpose.  A changed tenant, purpose, nonce or tag therefore
raises :class:`RecordAuthenticationError`, which is also a
:class:`~nacl.exceptions.CryptoError`.

.. code-block:: python

    from nacl.encoding import Base64Encoder
    from nacl.record_migration import (
        LegacyLayout,
        LegacyRecord,
        decrypt_new_record,
        migrate_batches,
    )
    from nacl.secret import Aead, SecretBox

    secret_box = SecretBox(key)
    aead = Aead(key)
    source = [
        LegacyRecord(
            record_id="record-1",
            tenant="tenant-a",
            purpose="audit-log",
            layout=LegacyLayout.COMBINED,
            payload=stored_payload,
            encoder=Base64Encoder,
        ),
    ]

    for batch in migrate_batches(
        source,
        legacy_box=secret_box,
        aead=aead,
        batch_size=100,
    ):
        write_batch_to_storage([record.to_dict() for record in batch])

    for record in migrated_records:
        plaintext = decrypt_new_record(record, aead)

Batch migrations authenticate records already carrying
``CURRENT_VERSION`` instead of rewriting them.  ``migrate_in_place`` can
replace rows immediately; rerunning it after an interruption skips the
already-migrated rows and resumes with the remaining legacy rows.

Reference
---------

.. automodule:: nacl.record_migration
   :members:
   :member-order: bysource
   :show-inheritance:
