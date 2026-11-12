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
from __future__ import annotations

import binascii
import logging
import re

import nacl.encoding
import nacl.public
import nacl.secret
import nacl.signing

# Fixed, non-secret fake key material. The printable variant proves that even
# keys with no escaped bytes cannot appear verbatim in a rendered object.
RAW_PRIVATE = b"\x11" * nacl.public.PrivateKey.SIZE
RAW_PEER = b"\x22" * nacl.public.PrivateKey.SIZE
RAW_SYMMETRIC = b"0123456789abcdefABCDEFghijklmnop"
RAW_AEAD = b"\xaa" * nacl.secret.Aead.KEY_SIZE
RAW_SIGNING = b"\x44" * 32


def _secret_fragments(raw):
    """Every representation of secret bytes that must never be rendered."""
    fragments = [raw.decode("latin-1"), binascii.hexlify(raw).decode("ascii")]
    return fragments


def _renderings(obj):
    return [
        str(obj),
        repr(obj),
        f"{obj}",
        "%s" % obj,
        str([obj]),
        str((obj,)),
        str({"key": obj}),
    ]


def test_secret_objects_are_redacted():
    private = nacl.public.PrivateKey(RAW_PRIVATE)
    peer = nacl.public.PrivateKey(RAW_PEER)
    signing = nacl.signing.SigningKey(RAW_SIGNING)
    box = nacl.public.Box(private, peer.public_key)
    cases = [
        (private, [RAW_PRIVATE]),
        (box, [bytes(box)]),
        (nacl.secret.SecretBox(RAW_SYMMETRIC), [RAW_SYMMETRIC]),
        (nacl.secret.Aead(RAW_AEAD), [RAW_AEAD]),
        (signing, [RAW_SIGNING]),
        (
            nacl.public.SealedBox(private),
            [RAW_PRIVATE, bytes(private.public_key)],
        ),
    ]

    for obj, secrets in cases:
        rendered = "\n".join(_renderings(obj))
        assert "[redacted]" in rendered
        assert type(obj).__name__ in rendered
        for raw in secrets:
            for fragment in _secret_fragments(raw):
                assert fragment not in rendered
        # No escaped byte notation such as \x11 or \xaa may appear.
        assert re.search(r"\\x[0-9a-fA-F]{2}", rendered) is None


def test_secret_objects_do_not_leak_into_logs(caplog):
    private = nacl.public.PrivateKey(RAW_PRIVATE)
    symmetric = nacl.secret.SecretBox(RAW_SYMMETRIC)
    signing = nacl.signing.SigningKey(RAW_SIGNING)

    caplog.set_level(logging.DEBUG)
    logging.getLogger("nacl.redaction.test").debug(
        "rendered: %s / %r / %s", private, symmetric, [signing]
    )
    message = caplog.records[0].getMessage()

    assert "[redacted]" in message
    for raw in (RAW_PRIVATE, RAW_SYMMETRIC, RAW_SIGNING):
        for fragment in _secret_fragments(raw):
            assert fragment not in message


def test_redacted_repr_has_no_address_and_is_stable():
    private = nacl.public.PrivateKey(RAW_PRIVATE)
    assert repr(private) == str(private)
    assert "object at 0x" not in repr(private)
    assert type(private).__name__ in repr(private)


def test_secret_byte_interfaces_remain_available():
    private = nacl.public.PrivateKey(RAW_PRIVATE)
    box = nacl.public.Box(
        private, nacl.public.PrivateKey(RAW_PEER).public_key
    )
    symmetric = nacl.secret.SecretBox(RAW_SYMMETRIC)
    aead = nacl.secret.Aead(RAW_AEAD)
    signing = nacl.signing.SigningKey(RAW_SIGNING)

    assert bytes(private) == RAW_PRIVATE
    assert private.encode(
        encoder=nacl.encoding.HexEncoder
    ) == binascii.hexlify(RAW_PRIVATE)
    assert bytes(box) == box.shared_key()
    assert bytes(nacl.public.Box.decode(box.encode())) == bytes(box)
    assert bytes(symmetric) == RAW_SYMMETRIC
    assert bytes(aead) == RAW_AEAD
    assert bytes(signing) == RAW_SIGNING
    assert signing.encode(
        encoder=nacl.encoding.HexEncoder
    ) == binascii.hexlify(RAW_SIGNING)


def test_public_key_display_is_preserved():
    public = nacl.public.PrivateKey(RAW_PRIVATE).public_key
    verify = nacl.signing.SigningKey(RAW_SIGNING).verify_key

    assert str(public) == str(bytes(public))
    assert f"{public}" == str(bytes(public))
    assert "%s" % public == str(bytes(public))
    assert str(verify) == str(bytes(verify))
    # Public keys intentionally keep their byte-rendering behavior.
    assert repr(public).startswith("<nacl.public.PublicKey object at 0x")
