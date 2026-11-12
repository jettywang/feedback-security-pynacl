"""Migrate persisted :class:`SecretBox` records to versioned :class:`Aead`.

The two supported legacy layouts differ in exactly where the configured
encoder was applied:

``LegacyLayout.COMBINED``
    The stored payload is ``bytes(SecretBox.encrypt(...))``.  The encoder was
    applied to the concatenation ``nonce + ciphertext`` **once**, so the
    payload must be decoded once and then split at
    :attr:`SecretBox.NONCE_SIZE`.

``LegacyLayout.SPLIT``
    The nonce and ciphertext are stored separately.  ``nonce_encoded``
    declares whether the nonce went through the encoder.  When it is true,
    the stored values are ``EncryptedMessage.nonce`` and
    ``EncryptedMessage.ciphertext``; both are decoded once.  When it is false,
    the stored nonce is the raw nonce passed to :meth:`SecretBox.encrypt` and
    only ``EncryptedMessage.ciphertext`` is decoded.

Readers never guess a layout and never retry another decoder.  Each record
declares both its layout and the encoder that was used when it was written.
Applying an encoder twice (or not at all) turns a valid record into an
authentication failure, which is the intended fail-closed behaviour.

New records always declare ``version == CURRENT_VERSION``.  The record's
tenant and purpose are part of the AEAD associated data.  The associated data
is length-prefixed and includes the version, so changing any of those values
-- including relabelling the version -- makes decryption fail with
:class:`RecordAuthenticationError` (a :class:`~nacl.exceptions.CryptoError`).

Legacy records cannot authenticate their tenant or purpose.  During
migration, the tenant and purpose stored next to the legacy record MUST come
from trusted application context, not from unauthenticated user input; once
re-encrypted they are protected by the AEAD tag.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable
from typing import Iterable
from typing import Iterator
from typing import MutableSequence
from typing import Sequence
from typing import TypeVar
from typing import Union

from nacl import encoding
from nacl import exceptions as exc
from nacl.secret import Aead
from nacl.secret import SecretBox

CURRENT_VERSION = 2
LEGACY_VERSION = 1
SUPPORTED_VERSIONS = frozenset({CURRENT_VERSION})

__all__ = [
    "CURRENT_VERSION",
    "LEGACY_VERSION",
    "LegacyLayout",
    "LegacyLayoutError",
    "LegacyRecord",
    "NewRecord",
    "RecordAuthenticationError",
    "RecordMigrationError",
    "UnsupportedVersionError",
    "authenticated_context",
    "decode_legacy_parts",
    "decrypt_legacy_record",
    "decrypt_new_record",
    "encrypt_new_record",
    "iter_batches",
    "migrate_batch",
    "migrate_batches",
    "migrate_in_place",
    "migrate_record",
    "verify_new_record",
]

Record = Union["LegacyRecord", "NewRecord"]
_RecordT = TypeVar("_RecordT")

_AAD_DOMAIN = b"pynacl-record-migration\x00"
_NONCE_FACTORY = Callable[[], bytes]


class LegacyLayout(str, Enum):
    """How the encoder was applied to a persisted legacy record."""

    COMBINED = "combined"
    SPLIT = "split"


class RecordMigrationError(Exception):
    """Base class for record migration errors."""


class UnsupportedVersionError(RecordMigrationError, ValueError):
    """The declared record version has no parser in this migration path."""


class RecordAuthenticationError(RecordMigrationError, exc.CryptoError):
    """The record did not authenticate for its declared context."""


class LegacyLayoutError(RecordMigrationError, ValueError):
    """The legacy layout declaration or its fields are invalid."""


def _coerce_layout(value: LegacyLayout | str) -> LegacyLayout:
    if isinstance(value, LegacyLayout):
        return value
    try:
        return LegacyLayout(value)
    except ValueError:
        raise LegacyLayoutError(
            f"unsupported legacy layout: {value!r}"
        ) from None


def _check_text(name: str, value: str) -> None:
    if not isinstance(value, str):
        raise exc.TypeError(f"{name} must be a str")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise exc.ValueError(f"{name} must be valid UTF-8") from error


def _check_bytes(name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise exc.TypeError(f"{name} must be bytes")


def _check_version(version: int) -> None:
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version < 0
        or version >= 1 << 64
    ):
        raise exc.TypeError("version must be an unsigned 64-bit integer")


def authenticated_context(version: int, tenant: str, purpose: str) -> bytes:
    """Return the unambiguous AEAD associated data for a record context.

    Each variable-length field is length-prefixed, so distinct
    ``(version, tenant, purpose)`` tuples cannot produce the same bytes by
    moving bytes across field boundaries.
    """

    _check_version(version)
    _check_text("tenant", tenant)
    _check_text("purpose", purpose)
    tenant_bytes = tenant.encode("utf-8")
    purpose_bytes = purpose.encode("utf-8")
    if len(tenant_bytes) >= 1 << 32 or len(purpose_bytes) >= 1 << 32:
        raise exc.ValueError(
            "tenant and purpose must be shorter than 2**32 bytes"
        )
    return (
        _AAD_DOMAIN
        + version.to_bytes(8, "big")
        + len(tenant_bytes).to_bytes(4, "big")
        + tenant_bytes
        + len(purpose_bytes).to_bytes(4, "big")
        + purpose_bytes
    )


def _check_encoder(encoder: encoding.Encoder) -> None:
    try:
        encoder.encode
        encoder.decode
    except AttributeError:
        raise exc.TypeError(
            "encoder must provide encode and decode methods"
        ) from None


def _dict_encoder(value: object) -> encoding.Encoder:
    try:
        encoder: encoding.Encoder = value  # type: ignore[assignment]
        _check_encoder(encoder)
    except (AttributeError, TypeError):
        raise exc.TypeError(
            "encoder must provide encode and decode methods"
        ) from None
    return encoder


def _require_bytes(value: bytes | None, name: str) -> bytes:
    if value is None:
        raise LegacyLayoutError(f"{name} is required for this layout")
    _check_bytes(name, value)
    return value


@dataclass(frozen=True)
class LegacyRecord:
    """A persisted SecretBox record and its trusted context.

    ``record_id``, ``tenant`` and ``purpose`` describe the row.  The tenant and
    purpose are *claims* taken from the storage layer; the legacy format cannot
    authenticate them.
    """

    record_id: str
    tenant: str
    purpose: str
    layout: LegacyLayout | str
    version: int = LEGACY_VERSION
    payload: bytes | None = None
    nonce: bytes | None = None
    ciphertext: bytes | None = None
    encoder: encoding.Encoder = encoding.RawEncoder
    nonce_encoded: bool = True

    def __post_init__(self) -> None:
        _check_text("record_id", self.record_id)
        _check_text("tenant", self.tenant)
        _check_text("purpose", self.purpose)
        if self.version != LEGACY_VERSION or isinstance(self.version, bool):
            raise UnsupportedVersionError(
                f"legacy record declares unsupported version {self.version!r}"
            )
        _check_encoder(self.encoder)
        if not isinstance(self.nonce_encoded, bool):
            raise exc.TypeError("nonce_encoded must be a bool")
        layout = _coerce_layout(self.layout)
        object.__setattr__(self, "layout", layout)

        if layout is LegacyLayout.COMBINED:
            if self.payload is None:
                raise LegacyLayoutError(
                    "payload is required for combined layout"
                )
            _check_bytes("payload", self.payload)
            if self.nonce is not None or self.ciphertext is not None:
                raise LegacyLayoutError(
                    "combined layout must not also contain nonce/ciphertext"
                )
        else:
            if self.payload is not None:
                raise LegacyLayoutError(
                    "split layouts must not contain a combined payload"
                )
            if self.nonce is None or self.ciphertext is None:
                raise LegacyLayoutError(
                    "split layouts require both nonce and ciphertext"
                )
            _check_bytes("nonce", self.nonce)
            _check_bytes("ciphertext", self.ciphertext)

    def to_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "record_id": self.record_id,
            "version": LEGACY_VERSION,
            "layout": _coerce_layout(self.layout).value,
            "tenant": self.tenant,
            "purpose": self.purpose,
            "encoder": self.encoder,
            "nonce_encoded": self.nonce_encoded,
        }
        if self.payload is not None:
            result["payload"] = self.payload
        if self.nonce is not None:
            result["nonce"] = self.nonce
        if self.ciphertext is not None:
            result["ciphertext"] = self.ciphertext
        return result

    @classmethod
    def from_dict(cls, record: dict[str, object]) -> LegacyRecord:
        version = record.get("version", LEGACY_VERSION)
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != LEGACY_VERSION
        ):
            raise UnsupportedVersionError(
                f"legacy record declares unsupported version {version!r}"
            )
        return cls(
            record_id=_dict_text(record, "record_id"),
            tenant=_dict_text(record, "tenant"),
            purpose=_dict_text(record, "purpose"),
            layout=_dict_text(record, "layout"),
            version=version,
            payload=_dict_optional_bytes(record, "payload"),
            nonce=_dict_optional_bytes(record, "nonce"),
            ciphertext=_dict_optional_bytes(record, "ciphertext"),
            encoder=_dict_encoder(record.get("encoder", encoding.RawEncoder)),
            nonce_encoded=_dict_bool(record, "nonce_encoded", True),
        )


@dataclass(frozen=True)
class NewRecord:
    """A versioned Aead record; its context is protected by the AEAD tag."""

    record_id: str
    version: int
    tenant: str
    purpose: str
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        _check_text("record_id", self.record_id)
        _check_version(self.version)
        _check_text("tenant", self.tenant)
        _check_text("purpose", self.purpose)
        _check_bytes("nonce", self.nonce)
        _check_bytes("ciphertext", self.ciphertext)
        if len(self.nonce) != Aead.NONCE_SIZE:
            raise exc.ValueError(
                f"nonce must be exactly {Aead.NONCE_SIZE} bytes long"
            )
        if len(self.ciphertext) < Aead.MACBYTES:
            raise exc.ValueError(
                f"ciphertext must be at least {Aead.MACBYTES} bytes long"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "version": self.version,
            "tenant": self.tenant,
            "purpose": self.purpose,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        }

    @classmethod
    def from_dict(cls, record: dict[str, object]) -> NewRecord:
        return cls(
            record_id=_dict_text(record, "record_id"),
            version=_dict_int(record, "version"),
            tenant=_dict_text(record, "tenant"),
            purpose=_dict_text(record, "purpose"),
            nonce=_dict_bytes(record, "nonce"),
            ciphertext=_dict_bytes(record, "ciphertext"),
        )


def _dict_value(record: dict[str, object], name: str) -> object:
    try:
        return record[name]
    except KeyError:
        raise LegacyLayoutError(f"record is missing {name!r}") from None


def _dict_text(record: dict[str, object], name: str) -> str:
    value = _dict_value(record, name)
    if not isinstance(value, str):
        raise exc.TypeError(f"{name} must be a str")
    return value


def _dict_int(record: dict[str, object], name: str) -> int:
    value = _dict_value(record, name)
    if not isinstance(value, int) or isinstance(value, bool):
        raise exc.TypeError(f"{name} must be an int")
    return value


def _dict_bool(record: dict[str, object], name: str, default: bool) -> bool:
    value = record.get(name, default)
    if not isinstance(value, bool):
        raise exc.TypeError(f"{name} must be a bool")
    return value


def _dict_bytes(record: dict[str, object], name: str) -> bytes:
    value = _dict_value(record, name)
    if not isinstance(value, bytes):
        raise exc.TypeError(f"{name} must be bytes")
    return value


def _dict_optional_bytes(record: dict[str, object], name: str) -> bytes | None:
    value = record.get(name)
    if value is None:
        return None
    if not isinstance(value, bytes):
        raise exc.TypeError(f"{name} must be bytes")
    return value


def _decode_field(
    encoder: encoding.Encoder,
    data: bytes,
    field: str,
) -> bytes:
    try:
        return encoder.decode(data)
    except Exception as error:
        raise LegacyLayoutError(
            f"could not decode legacy {field} with the declared encoder"
        ) from error


def decode_legacy_parts(
    record: LegacyRecord,
    encoder: encoding.Encoder | None = None,
) -> tuple[bytes, bytes]:
    """Return raw ``(nonce, ciphertext)`` for a declared legacy layout.

    This is the single deterministic read rule.  Every stored field that was
    encoder-produced is decoded exactly once; no field is decoded twice and
    no layout is auto-detected.
    """

    actual_encoder = record.encoder if encoder is None else encoder
    _check_encoder(actual_encoder)
    layout = _coerce_layout(record.layout)
    if layout is LegacyLayout.COMBINED:
        payload = _require_bytes(record.payload, "payload")
        combined = _decode_field(actual_encoder, payload, "payload")
        if len(combined) < SecretBox.NONCE_SIZE + SecretBox.MACBYTES:
            raise LegacyLayoutError(
                "combined payload is too short to contain nonce and MAC"
            )
        return (
            combined[: SecretBox.NONCE_SIZE],
            combined[SecretBox.NONCE_SIZE :],
        )

    if layout is LegacyLayout.SPLIT:
        stored_nonce = _require_bytes(record.nonce, "nonce")
        if record.nonce_encoded:
            nonce = _decode_field(actual_encoder, stored_nonce, "nonce")
        else:
            nonce = stored_nonce
        ciphertext = _decode_field(
            actual_encoder,
            _require_bytes(record.ciphertext, "ciphertext"),
            "ciphertext",
        )
        return nonce, ciphertext

    raise LegacyLayoutError(f"unsupported legacy layout: {layout.value!r}")


def decrypt_legacy_record(
    record: LegacyRecord,
    legacy_box: SecretBox,
    encoder: encoding.Encoder | None = None,
) -> bytes:
    """Decrypt one legacy record using its declared layout and encoder."""

    nonce, ciphertext = decode_legacy_parts(record, encoder)
    return legacy_box.decrypt(
        ciphertext,
        nonce,
        encoder=encoding.RawEncoder,
    )


# Convenient aliases matching the read/write vocabulary of the migration.
read_legacy_record = decrypt_legacy_record


def encrypt_new_record(
    record_id: str,
    plaintext: bytes,
    *,
    tenant: str,
    purpose: str,
    aead: Aead,
    version: int = CURRENT_VERSION,
    nonce: bytes | None = None,
) -> NewRecord:
    """Write one explicitly versioned Aead record.

    Only :data:`CURRENT_VERSION` can be written.  ``tenant`` and ``purpose``
    are placed in the AEAD associated data and are also stored as routing
    metadata; changing either stored value invalidates authentication.
    """

    _check_text("record_id", record_id)
    _check_text("tenant", tenant)
    _check_text("purpose", purpose)
    _check_bytes("plaintext", plaintext)
    _check_version(version)
    if version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersionError(
            f"cannot write unsupported version {version!r}; "
            f"supported versions are {sorted(SUPPORTED_VERSIONS)!r}"
        )

    aad = authenticated_context(version, tenant, purpose)
    encrypted = aead.encrypt(plaintext, aad, nonce)
    return NewRecord(
        record_id=record_id,
        version=version,
        tenant=tenant,
        purpose=purpose,
        nonce=encrypted.nonce,
        ciphertext=encrypted.ciphertext,
    )


# Aliases: callers often name this operation by its storage side effect.
write_new_record = encrypt_new_record


def decrypt_new_record(
    record: NewRecord,
    aead: Aead,
    *,
    expected_tenant: str | None = None,
    expected_purpose: str | None = None,
) -> bytes:
    """Decrypt a new record using only its declared version.

    An unsupported declared version is rejected before any decryption
    attempt.  The stored tenant/purpose are authenticated; optional expected
    values additionally bind the record to the caller's current context.
    """

    if record.version not in SUPPORTED_VERSIONS:
        raise UnsupportedVersionError(
            f"record declares unsupported version {record.version!r}; "
            f"supported versions are {sorted(SUPPORTED_VERSIONS)!r}"
        )

    if expected_tenant is not None and record.tenant != expected_tenant:
        raise RecordAuthenticationError(
            "record authentication failed: tenant mismatch"
        )
    if expected_purpose is not None and record.purpose != expected_purpose:
        raise RecordAuthenticationError(
            "record authentication failed: purpose mismatch"
        )

    aad = authenticated_context(record.version, record.tenant, record.purpose)
    try:
        return aead.decrypt(record.ciphertext, aad, record.nonce)
    except exc.CryptoError as error:
        raise RecordAuthenticationError(
            "record authentication failed"
        ) from error


read_new_record = decrypt_new_record


def verify_new_record(
    record: NewRecord,
    aead: Aead,
    *,
    expected_tenant: str | None = None,
    expected_purpose: str | None = None,
) -> None:
    """Authenticate a new record without returning its plaintext."""

    decrypt_new_record(
        record,
        aead,
        expected_tenant=expected_tenant,
        expected_purpose=expected_purpose,
    )


def migrate_record(
    record: LegacyRecord,
    *,
    legacy_box: SecretBox,
    aead: Aead,
    encoder: encoding.Encoder | None = None,
    nonce: bytes | None = None,
) -> NewRecord:
    """Decrypt one legacy record and rewrite it as a versioned Aead record."""

    plaintext = decrypt_legacy_record(record, legacy_box, encoder)
    return encrypt_new_record(
        record.record_id,
        plaintext,
        tenant=record.tenant,
        purpose=record.purpose,
        aead=aead,
        nonce=nonce,
    )


def iter_batches(
    records: Iterable[_RecordT],
    batch_size: int,
) -> Iterator[list[_RecordT]]:
    """Yield consecutive lists of at most ``batch_size`` records."""

    if not isinstance(batch_size, int) or isinstance(batch_size, bool):
        raise exc.TypeError("batch_size must be an int")
    if batch_size < 1:
        raise exc.ValueError("batch_size must be at least 1")

    batch: list[_RecordT] = []
    for record in records:
        batch.append(record)
        if len(batch) == batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def migrate_batch(
    records: Sequence[Record],
    *,
    legacy_box: SecretBox,
    aead: Aead,
    encoder: encoding.Encoder | None = None,
    nonce_factory: _NONCE_FACTORY | None = None,
) -> list[NewRecord]:
    """Migrate one batch, skipping records that are already versioned.

    Existing :class:`NewRecord` instances are authenticated rather than
    rewritten, which makes a rerun after an interrupted migration idempotent.

    When ``encoder`` is omitted, each :class:`LegacyRecord` uses its own
    declared encoder.  A supplied ``nonce_factory`` MUST return a unique
    XChaCha20 nonce for every migrated record; omit it to use random nonces.
    """

    migrated: list[NewRecord] = []
    for record in records:
        if isinstance(record, NewRecord):
            verify_new_record(record, aead)
            migrated.append(record)
            continue
        if not isinstance(record, LegacyRecord):
            raise exc.TypeError(
                "records must contain LegacyRecord or NewRecord instances"
            )
        nonce = nonce_factory() if nonce_factory is not None else None
        migrated.append(
            migrate_record(
                record,
                legacy_box=legacy_box,
                aead=aead,
                encoder=encoder,
                nonce=nonce,
            )
        )
    return migrated


def migrate_batches(
    records: Iterable[Record],
    *,
    legacy_box: SecretBox,
    aead: Aead,
    encoder: encoding.Encoder | None = None,
    batch_size: int = 100,
    nonce_factory: _NONCE_FACTORY | None = None,
) -> Iterator[list[NewRecord]]:
    """Read legacy records in batches and yield versioned replacements."""

    for batch in iter_batches(records, batch_size):
        yield migrate_batch(
            batch,
            legacy_box=legacy_box,
            aead=aead,
            encoder=encoder,
            nonce_factory=nonce_factory,
        )


def migrate_in_place(
    records: MutableSequence[Record],
    *,
    legacy_box: SecretBox,
    aead: Aead,
    encoder: encoding.Encoder | None = None,
    batch_size: int = 100,
    nonce_factory: _NONCE_FACTORY | None = None,
    max_migrations: int | None = None,
) -> list[NewRecord]:
    """Rewrite a mutable source in batches and return the processed prefix.

    Each successfully migrated legacy record is replaced immediately, so an
    interruption (simulated with ``max_migrations``) leaves the source with a
    mix of old and new records.  A subsequent run authenticates and skips the
    already-migrated ones and resumes with the remaining legacy records.
    """

    if not isinstance(batch_size, int) or isinstance(batch_size, bool):
        raise exc.TypeError("batch_size must be an int")
    if batch_size < 1:
        raise exc.ValueError("batch_size must be at least 1")

    if max_migrations is not None:
        if (
            not isinstance(max_migrations, int)
            or isinstance(max_migrations, bool)
            or max_migrations < 0
        ):
            raise exc.ValueError("max_migrations must be a non-negative int")

    done: list[NewRecord] = []
    migrated_count = 0

    for start in range(0, len(records), batch_size):
        chunk = records[start : start + batch_size]
        for offset, record in enumerate(chunk):
            if isinstance(record, NewRecord):
                verify_new_record(record, aead)
                done.append(record)
                continue
            if not isinstance(record, LegacyRecord):
                raise exc.TypeError(
                    "records must contain LegacyRecord or NewRecord instances"
                )
            if max_migrations is not None and migrated_count >= max_migrations:
                return done
            nonce = nonce_factory() if nonce_factory is not None else None
            replacement = migrate_record(
                record,
                legacy_box=legacy_box,
                aead=aead,
                encoder=encoder,
                nonce=nonce,
            )
            records[start + offset] = replacement
            done.append(replacement)
            migrated_count += 1

    return done
