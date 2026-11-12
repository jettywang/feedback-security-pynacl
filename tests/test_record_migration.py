from __future__ import annotations

from dataclasses import replace

import pytest

from nacl import encoding
from nacl import exceptions as exc
from nacl.record_migration import CURRENT_VERSION
from nacl.record_migration import LEGACY_VERSION
from nacl.record_migration import LegacyLayout
from nacl.record_migration import LegacyLayoutError
from nacl.record_migration import LegacyRecord
from nacl.record_migration import NewRecord
from nacl.record_migration import RecordAuthenticationError
from nacl.record_migration import UnsupportedVersionError
from nacl.record_migration import authenticated_context
from nacl.record_migration import decode_legacy_parts
from nacl.record_migration import decrypt_legacy_record
from nacl.record_migration import decrypt_new_record
from nacl.record_migration import encrypt_new_record
from nacl.record_migration import iter_batches
from nacl.record_migration import migrate_batch
from nacl.record_migration import migrate_batches
from nacl.record_migration import migrate_in_place
from nacl.record_migration import migrate_record
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


def fixed_legacy_records() -> tuple[LegacyRecord, LegacyRecord]:
    """Two deterministic legacy rows covering both storage layouts.

    The combined row was written with Base64Encoder.  The split row was
    written with HexEncoder and stores the encoded ``EncryptedMessage.nonce``
    and ``EncryptedMessage.ciphertext`` attributes.
    """

    secret_box = SecretBox(SECRETBOX_KEY)
    encoded_combined = secret_box.encrypt(
        PLAINTEXT_1, LEGACY_NONCE_1, encoder=encoding.Base64Encoder
    )
    encoded_split = secret_box.encrypt(
        PLAINTEXT_2, LEGACY_NONCE_2, encoder=encoding.HexEncoder
    )

    combined = LegacyRecord(
        record_id="record-1",
        tenant="tenant-a",
        purpose="audit-log",
        layout=LegacyLayout.COMBINED,
        payload=bytes(encoded_combined),
        encoder=encoding.Base64Encoder,
    )
    split = LegacyRecord(
        record_id="record-2",
        tenant="tenant-b",
        purpose="billing",
        layout=LegacyLayout.SPLIT,
        nonce=encoded_split.nonce,
        ciphertext=encoded_split.ciphertext,
        encoder=encoding.HexEncoder,
    )
    return combined, split


@pytest.fixture()
def legacy_records() -> tuple[LegacyRecord, LegacyRecord]:
    return fixed_legacy_records()


@pytest.fixture()
def secret_box() -> SecretBox:
    return SecretBox(SECRETBOX_KEY)


@pytest.fixture()
def aead() -> Aead:
    return Aead(AEAD_KEY)


def test_legacy_read_rules_cover_both_layouts(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    secret_box: SecretBox,
) -> None:
    combined, split = legacy_records
    raw_1 = secret_box.encrypt(PLAINTEXT_1, LEGACY_NONCE_1)
    raw_2 = secret_box.encrypt(PLAINTEXT_2, LEGACY_NONCE_2)

    assert decode_legacy_parts(combined) == (
        LEGACY_NONCE_1,
        raw_1.ciphertext,
    )
    assert decrypt_legacy_record(combined, secret_box) == PLAINTEXT_1

    assert decode_legacy_parts(split) == (
        LEGACY_NONCE_2,
        raw_2.ciphertext,
    )
    assert decrypt_legacy_record(split, secret_box) == PLAINTEXT_2


def test_legacy_split_with_raw_nonce_decodes_nonce_zero_times(
    secret_box: SecretBox,
) -> None:
    encrypted = secret_box.encrypt(
        PLAINTEXT_2, LEGACY_NONCE_2, encoder=encoding.Base64Encoder
    )
    raw = secret_box.encrypt(PLAINTEXT_2, LEGACY_NONCE_2)
    record = LegacyRecord(
        record_id="record-raw-nonce",
        tenant="tenant-b",
        purpose="billing",
        layout=LegacyLayout.SPLIT,
        nonce=LEGACY_NONCE_2,
        ciphertext=encrypted.ciphertext,
        encoder=encoding.Base64Encoder,
        nonce_encoded=False,
    )

    assert decode_legacy_parts(record) == (LEGACY_NONCE_2, raw.ciphertext)
    assert decrypt_legacy_record(record, secret_box) == PLAINTEXT_2


def test_component_encoded_fields_decode_exactly_once(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    secret_box: SecretBox,
) -> None:
    combined, _ = legacy_records
    # The combined payload only decrypts with the encoder used to write it.
    with pytest.raises(exc.CryptoError):
        decrypt_legacy_record(combined, secret_box, encoding.RawEncoder)
    with pytest.raises(LegacyLayoutError):
        decrypt_legacy_record(combined, secret_box, encoding.HexEncoder)


def test_new_record_roundtrip_and_explicit_version(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    aead: Aead,
) -> None:
    for record, nonce, plaintext in zip(
        legacy_records,
        (AEAD_NONCE_1, AEAD_NONCE_2),
        (PLAINTEXT_1, PLAINTEXT_2),
    ):
        new_record = encrypt_new_record(
            record.record_id,
            plaintext,
            tenant=record.tenant,
            purpose=record.purpose,
            aead=aead,
            nonce=nonce,
        )

        assert new_record.version == CURRENT_VERSION
        assert new_record.to_dict()["version"] == CURRENT_VERSION
        assert decrypt_new_record(new_record, aead) == plaintext
        assert (
            decrypt_new_record(
                new_record,
                aead,
                expected_tenant=record.tenant,
                expected_purpose=record.purpose,
            )
            == plaintext
        )


def test_error_classes_separate_input_errors_from_auth_failures() -> None:
    assert issubclass(RecordAuthenticationError, exc.CryptoError)
    assert issubclass(UnsupportedVersionError, ValueError)
    assert not issubclass(UnsupportedVersionError, exc.CryptoError)
    assert issubclass(LegacyLayoutError, ValueError)
    assert not issubclass(LegacyLayoutError, exc.CryptoError)


def test_wrong_tenant_reports_authentication_failure(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    aead: Aead,
) -> None:
    combined, _ = legacy_records
    new_record = encrypt_new_record(
        combined.record_id,
        PLAINTEXT_1,
        tenant=combined.tenant,
        purpose=combined.purpose,
        aead=aead,
        nonce=AEAD_NONCE_1,
    )

    tampered = replace(new_record, tenant="tenant-typo")
    with pytest.raises(RecordAuthenticationError) as caught:
        decrypt_new_record(tampered, aead)
    assert isinstance(caught.value, exc.CryptoError)

    with pytest.raises(RecordAuthenticationError):
        decrypt_new_record(new_record, aead, expected_tenant="tenant-typo")

    tampered_purpose = replace(new_record, purpose="billing")
    with pytest.raises(RecordAuthenticationError):
        decrypt_new_record(tampered_purpose, aead)


def test_wrong_nonce_reports_authentication_failure(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    aead: Aead,
) -> None:
    _, split = legacy_records
    new_record = encrypt_new_record(
        split.record_id,
        PLAINTEXT_2,
        tenant=split.tenant,
        purpose=split.purpose,
        aead=aead,
        nonce=AEAD_NONCE_2,
    )

    with pytest.raises(RecordAuthenticationError) as caught:
        decrypt_new_record(replace(new_record, nonce=AEAD_NONCE_1), aead)
    assert isinstance(caught.value, exc.CryptoError)


def test_new_records_are_parsed_only_by_declared_version(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    aead: Aead,
) -> None:
    combined, _ = legacy_records
    new_record = encrypt_new_record(
        combined.record_id,
        PLAINTEXT_1,
        tenant=combined.tenant,
        purpose=combined.purpose,
        aead=aead,
        nonce=AEAD_NONCE_1,
    )

    for wrong_version in (LEGACY_VERSION, 0, 3, 99):
        with pytest.raises(UnsupportedVersionError):
            decrypt_new_record(
                replace(new_record, version=wrong_version), aead
            )
        with pytest.raises(UnsupportedVersionError):
            encrypt_new_record(
                combined.record_id,
                PLAINTEXT_1,
                tenant=combined.tenant,
                purpose=combined.purpose,
                aead=aead,
                version=wrong_version,
            )


def test_context_is_unambiguous_and_version_is_authenticated(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    aead: Aead,
) -> None:
    combined, _ = legacy_records
    first = encrypt_new_record(
        combined.record_id,
        PLAINTEXT_1,
        tenant=combined.tenant,
        purpose=combined.purpose,
        aead=aead,
        nonce=AEAD_NONCE_1,
    )
    second = encrypt_new_record(
        combined.record_id,
        PLAINTEXT_1,
        tenant=combined.tenant,
        purpose=combined.purpose,
        aead=aead,
        nonce=AEAD_NONCE_1,
    )
    assert first.ciphertext == second.ciphertext
    assert authenticated_context(
        CURRENT_VERSION, combined.tenant, combined.purpose
    ) != authenticated_context(
        LEGACY_VERSION, combined.tenant, combined.purpose
    )
    assert authenticated_context(
        CURRENT_VERSION, "a:b", "c"
    ) != authenticated_context(CURRENT_VERSION, "a", "b:c")


def test_batched_migration_of_two_fixed_records(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    secret_box: SecretBox,
    aead: Aead,
) -> None:
    batches = list(
        migrate_batches(
            legacy_records,
            legacy_box=secret_box,
            aead=aead,
            batch_size=1,
            nonce_factory=iter((AEAD_NONCE_1, AEAD_NONCE_2)).__next__,
        )
    )
    assert len(batches) == 2
    assert all(len(batch) == 1 for batch in batches)
    migrated_one, migrated_two = (batch[0] for batch in batches)
    assert migrated_one.version == CURRENT_VERSION
    assert migrated_two.version == CURRENT_VERSION
    assert decrypt_new_record(migrated_one, aead) == PLAINTEXT_1
    assert decrypt_new_record(migrated_two, aead) == PLAINTEXT_2


def test_batch_size_is_rejected(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    secret_box: SecretBox,
    aead: Aead,
) -> None:
    with pytest.raises(exc.ValueError):
        list(iter_batches(legacy_records, 0))
    with pytest.raises(exc.ValueError):
        migrate_in_place(
            list(legacy_records),
            legacy_box=secret_box,
            aead=aead,
            batch_size=0,
        )


def test_batch_helpers_and_skip_existing_records(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    secret_box: SecretBox,
    aead: Aead,
) -> None:
    assert list(iter_batches([1, 2, 3], 2)) == [[1, 2], [3]]

    migrated = migrate_record(
        legacy_records[0],
        legacy_box=secret_box,
        aead=aead,
        nonce=AEAD_NONCE_1,
    )
    unchanged = migrate_batch([migrated], legacy_box=secret_box, aead=aead)
    assert unchanged == [migrated]
    assert unchanged[0].nonce == AEAD_NONCE_1
    assert unchanged[0].ciphertext == migrated.ciphertext


def test_interrupted_migration_resumes_without_rewriting(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    secret_box: SecretBox,
    aead: Aead,
) -> None:
    source: list[LegacyRecord | NewRecord] = list(legacy_records)
    nonces = iter((AEAD_NONCE_1, AEAD_NONCE_2))

    first_run = migrate_in_place(
        source,
        legacy_box=secret_box,
        aead=aead,
        max_migrations=1,
        nonce_factory=lambda: next(nonces),
    )
    assert len(first_run) == 1
    assert isinstance(source[0], NewRecord)
    assert isinstance(source[1], LegacyRecord)
    first_ciphertext = source[0].ciphertext
    first_nonce = source[0].nonce

    second_run = migrate_in_place(
        source,
        legacy_box=secret_box,
        aead=aead,
        nonce_factory=lambda: next(nonces),
    )
    first_after_rerun, second_after_rerun = source
    assert type(first_after_rerun) is NewRecord
    assert type(second_after_rerun) is NewRecord
    assert first_after_rerun.ciphertext == first_ciphertext
    assert first_after_rerun.nonce == first_nonce
    assert decrypt_new_record(first_after_rerun, aead) == PLAINTEXT_1
    assert decrypt_new_record(second_after_rerun, aead) == PLAINTEXT_2
    assert [record.record_id for record in second_run] == [
        "record-1",
        "record-2",
    ]


def test_dict_roundtrip_preserves_layout_and_version(
    legacy_records: tuple[LegacyRecord, LegacyRecord],
    aead: Aead,
) -> None:
    combined, split = legacy_records
    assert LegacyRecord.from_dict(combined.to_dict()) == combined
    assert LegacyRecord.from_dict(split.to_dict()) == split

    new_record = encrypt_new_record(
        combined.record_id,
        PLAINTEXT_1,
        tenant=combined.tenant,
        purpose=combined.purpose,
        aead=aead,
        nonce=AEAD_NONCE_1,
    )
    assert NewRecord.from_dict(new_record.to_dict()) == new_record
