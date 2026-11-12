"""Executable demo for the SecretBox-to-Aead record migration.

Run from the repository root with the project virtualenv:

    .venv/bin/python examples/record_migration_demo.py
"""

from __future__ import annotations

from dataclasses import replace

from nacl import encoding
from nacl import exceptions as exc
from nacl.record_migration import CURRENT_VERSION
from nacl.record_migration import LegacyLayout
from nacl.record_migration import LegacyRecord
from nacl.record_migration import NewRecord
from nacl.record_migration import RecordAuthenticationError
from nacl.record_migration import decode_legacy_parts
from nacl.record_migration import decrypt_legacy_record
from nacl.record_migration import decrypt_new_record
from nacl.record_migration import Record
from nacl.record_migration import migrate_batches
from nacl.record_migration import migrate_in_place
from nacl.secret import Aead
from nacl.secret import SecretBox

SECRETBOX_KEY = b"\x11" * SecretBox.KEY_SIZE
AEAD_KEY = b"\x22" * Aead.KEY_SIZE
LEGACY_NONCE_1 = bytes(range(24))
LEGACY_NONCE_2 = bytes(range(100, 124))
AEAD_NONCE_1 = b"\xa1" * Aead.NONCE_SIZE
AEAD_NONCE_2 = b"\xa2" * Aead.NONCE_SIZE
PLAINTEXT_1 = b"tenant-a:audit-log:record-1"
PLAINTEXT_2 = b"tenant-b:billing:record-2"


def build_legacy_records() -> tuple[LegacyRecord, LegacyRecord]:
    secret_box = SecretBox(SECRETBOX_KEY)
    combined = secret_box.encrypt(
        PLAINTEXT_1,
        LEGACY_NONCE_1,
        encoder=encoding.Base64Encoder,
    )
    split = secret_box.encrypt(
        PLAINTEXT_2,
        LEGACY_NONCE_2,
        encoder=encoding.HexEncoder,
    )
    return (
        LegacyRecord(
            record_id="record-1",
            tenant="tenant-a",
            purpose="audit-log",
            layout=LegacyLayout.COMBINED,
            payload=bytes(combined),
            encoder=encoding.Base64Encoder,
        ),
        LegacyRecord(
            record_id="record-2",
            tenant="tenant-b",
            purpose="billing",
            layout=LegacyLayout.SPLIT,
            nonce=split.nonce,
            ciphertext=split.ciphertext,
            encoder=encoding.HexEncoder,
        ),
    )


def main() -> None:
    secret_box = SecretBox(SECRETBOX_KEY)
    aead = Aead(AEAD_KEY)
    legacy_records = build_legacy_records()

    print("Before migration")
    for record in legacy_records:
        nonce, ciphertext = decode_legacy_parts(record)
        layout = LegacyLayout(record.layout)
        print(
            f"{record.record_id}: layout={layout.value}, "
            f"encoder={record.encoder.__name__}, "
            f"nonce_bytes={len(nonce)}, "
            f"ciphertext_bytes={len(ciphertext)}, "
            f"plaintext={decrypt_legacy_record(record, secret_box)!r}"
        )

    migrated_batches = list(
        migrate_batches(
            legacy_records,
            legacy_box=secret_box,
            aead=aead,
            batch_size=1,
            nonce_factory=iter((AEAD_NONCE_1, AEAD_NONCE_2)).__next__,
        )
    )
    migrated: list[NewRecord] = [batch[0] for batch in migrated_batches]

    print("\nAfter migration")
    for new_record in migrated:
        print(
            f"{new_record.record_id}: version={new_record.version}, "
            f"tenant={new_record.tenant!r}, "
            f"purpose={new_record.purpose!r}, "
            f"nonce={new_record.nonce.hex()}, "
            f"ciphertext={new_record.ciphertext.hex()[:32]}..., "
            f"plaintext={decrypt_new_record(new_record, aead)!r}"
        )

    print("\nTenant field changed")
    bad_tenant = replace(migrated[0], tenant="tenant-typo")
    try:
        decrypt_new_record(bad_tenant, aead)
    except RecordAuthenticationError as error:
        print(
            f"{type(error).__name__}: {error}; "
            f"CryptoError={isinstance(error, exc.CryptoError)}"
        )

    print("\nNonce mismatch")
    bad_nonce = replace(migrated[1], nonce=AEAD_NONCE_1)
    try:
        decrypt_new_record(bad_nonce, aead)
    except RecordAuthenticationError as error:
        print(f"{type(error).__name__}: {error}")

    print("\nInterrupted migration and rerun")
    source: list[Record] = list(build_legacy_records())
    nonces = iter((AEAD_NONCE_1, AEAD_NONCE_2))
    first_run = migrate_in_place(
        source,
        legacy_box=secret_box,
        aead=aead,
        max_migrations=1,
        nonce_factory=lambda: next(nonces),
    )
    print(
        "After interruption: "
        + ", ".join(
            f"{record.record_id}={type(record).__name__}" for record in source
        )
        + f"; processed={[record.record_id for record in first_run]}"
    )
    assert isinstance(source[0], NewRecord)
    first_nonce, first_ciphertext = source[0].nonce, source[0].ciphertext

    second_run = migrate_in_place(
        source,
        legacy_box=secret_box,
        aead=aead,
        nonce_factory=lambda: next(nonces),
    )
    print(
        "After rerun: "
        + ", ".join(
            f"{record.record_id}={type(record).__name__}" for record in source
        )
        + f"; processed={[record.record_id for record in second_run]}"
    )
    print(
        "First record was not rewritten: "
        + str(
            (source[0].nonce, source[0].ciphertext)
            == (first_nonce, first_ciphertext)
        )
    )
    current_records: list[NewRecord] = [
        record for record in source if isinstance(record, NewRecord)
    ]
    print(
        "All current records authenticate at version "
        f"{CURRENT_VERSION}: "
        + str(
            all(
                record.version == CURRENT_VERSION for record in current_records
            )
        )
    )


if __name__ == "__main__":
    main()
