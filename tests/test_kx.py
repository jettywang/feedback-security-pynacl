# Copyright 2018 Donald Stufft and individual contributors
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


import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis.strategies import binary

import nacl.bindings as b
import nacl.exceptions as exc
from nacl.public import (
    PrivateKey,
    PublicKey,
    SessionKeys,
    SessionRole,
    derive_session_keys,
    session_keys,
)
from nacl.secret import SecretBox


CLIENT_SEED = bytes(range(32))
SERVER_SEED = bytes(range(32, 64))
OTHER_PEER_SEED = bytes(range(64, 96))
CLIENT_NONCE = b"client nonce".ljust(SecretBox.NONCE_SIZE, b"\0")
SERVER_NONCE = b"server nonce".ljust(SecretBox.NONCE_SIZE, b"\0")


def _key_pair(seed: bytes) -> tuple[PrivateKey, PublicKey]:
    public_key, secret_key = b.crypto_kx_seed_keypair(seed)
    return PrivateKey(secret_key), PublicKey(public_key)


def test_crypto_kx_keypair():
    public_key, secret_key = b.crypto_kx_keypair()
    public_key_2, secret_key_2 = b.crypto_kx_keypair()
    assert public_key != public_key_2
    assert secret_key != secret_key_2


@given(
    binary(min_size=32, max_size=32),
    binary(min_size=32, max_size=32),
)
@settings(max_examples=100)
def test_crypto_kx_seed_keypair(seed1: bytes, seed2: bytes):
    seeded = b.crypto_kx_seed_keypair(seed1)
    seeded_other = b.crypto_kx_seed_keypair(seed2)
    if seed1 != seed2:
        assert seeded != seeded_other
    else:
        assert seeded == seeded_other


@given(
    binary(min_size=33, max_size=128),
)
@settings(max_examples=20, suppress_health_check=[HealthCheck.too_slow])
def test_crypto_kx_seed_keypair_seed_too_large(seed: bytes):
    with pytest.raises(exc.TypeError):
        b.crypto_kx_seed_keypair(seed)


@given(
    binary(min_size=0, max_size=31),
)
@settings(max_examples=20)
def test_crypto_kx_seed_keypair_seed_too_small(seed: bytes):
    with pytest.raises(exc.TypeError):
        b.crypto_kx_seed_keypair(seed)


@given(
    binary(min_size=32, max_size=32),
    binary(min_size=32, max_size=32),
)
@settings(max_examples=100)
def test_crypto_kx_session_keys(seed1: bytes, seed2: bytes):
    s_keys = b.crypto_kx_seed_keypair(seed1)
    c_keys = b.crypto_kx_seed_keypair(seed2)

    server_rx_key, server_tx_key = b.crypto_kx_server_session_keys(
        s_keys[0], s_keys[1], c_keys[0]
    )
    client_rx_key, client_tx_key = b.crypto_kx_client_session_keys(
        c_keys[0], c_keys[1], s_keys[0]
    )

    assert client_rx_key == server_tx_key
    assert server_rx_key == client_tx_key


def test_crypto_kx_session_wrong_key_lengths():
    s_keys = b.crypto_kx_keypair()
    c_keys = b.crypto_kx_keypair()

    # TODO: should invalid argument lengths (but correct types) raise ValueError?
    with pytest.raises(exc.TypeError):
        b.crypto_kx_server_session_keys(s_keys[0][:-1], s_keys[1], c_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_client_session_keys(c_keys[0][:-1], c_keys[1], s_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_server_session_keys(s_keys[0], s_keys[1][:-1], c_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_client_session_keys(c_keys[0], c_keys[1][:-1], s_keys[0])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_server_session_keys(s_keys[0], s_keys[1], c_keys[0][:-1])

    with pytest.raises(exc.TypeError):
        b.crypto_kx_client_session_keys(c_keys[0], c_keys[1], s_keys[0][:-1])


def test_session_keys_directional_round_trip():
    client_private, client_public = _key_pair(CLIENT_SEED)
    server_private, server_public = _key_pair(SERVER_SEED)

    client_keys = derive_session_keys(
        client_private, server_public, SessionRole.CLIENT
    )
    server_keys = derive_session_keys(
        server_private, client_public, SessionRole.SERVER
    )

    assert client_keys.send == server_keys.receive
    assert client_keys.receive == server_keys.send

    client_record = SecretBox(client_keys.send).encrypt(
        b"client to server", CLIENT_NONCE
    )
    assert (
        SecretBox(server_keys.receive).decrypt(client_record)
        == b"client to server"
    )
    with pytest.raises(exc.CryptoError):
        SecretBox(client_keys.receive).decrypt(client_record)

    server_record = SecretBox(server_keys.send).encrypt(
        b"server to client", SERVER_NONCE
    )
    assert (
        SecretBox(client_keys.receive).decrypt(server_record)
        == b"server to client"
    )
    with pytest.raises(exc.CryptoError):
        SecretBox(server_keys.receive).decrypt(server_record)

    # A raw echo can be decrypted with the same outgoing key, but not with
    # the key reserved for incoming traffic.
    assert SecretBox(client_keys.send).decrypt(client_record) == (
        b"client to server"
    )


def test_session_keys_match_low_level_bytes():
    client_private, client_public = _key_pair(CLIENT_SEED)
    _, server_public = _key_pair(SERVER_SEED)

    client_keys = derive_session_keys(
        client_private, server_public, "client"
    )
    low_level_rx, low_level_tx = b.crypto_kx_client_session_keys(
        bytes(client_public),
        bytes(client_private),
        bytes(server_public),
    )
    binding_keys = b.crypto_kx_session_keys(
        bytes(client_public),
        bytes(client_private),
        bytes(server_public),
        "client",
    )

    assert client_keys == SessionKeys(
        send=low_level_tx, receive=low_level_rx
    )
    assert binding_keys.send == low_level_tx
    assert binding_keys.receive == low_level_rx
    assert binding_keys.tx == low_level_tx
    assert binding_keys.rx == low_level_rx
    assert isinstance(bytes(client_keys.send), bytes)
    assert len(client_keys.send) == b.crypto_kx_SESSION_KEY_BYTES
    assert len(client_keys.receive) == b.crypto_kx_SESSION_KEY_BYTES


def test_session_keys_accept_raw_and_object_key_pairs():
    client_private, client_public = _key_pair(CLIENT_SEED)
    _, server_public = _key_pair(SERVER_SEED)

    expected = derive_session_keys(
        client_private, server_public, SessionRole.CLIENT
    )

    assert (
        derive_session_keys(
            (client_public, client_private), server_public, "client"
        )
        == expected
    )
    assert (
        derive_session_keys(
            (client_private, client_public), bytes(server_public), "client"
        )
        == expected
    )
    assert (
        derive_session_keys(
            (bytes(client_public), bytes(client_private)),
            server_public,
            "client",
        )
        == expected
    )
    assert SessionKeys.derive(
        client_private, server_public, SessionRole.CLIENT
    ) == expected
    assert (
        session_keys(client_private, server_public, SessionRole.CLIENT)
        == expected
    )


def test_session_keys_wrong_role_breaks_one_direction():
    client_private, client_public = _key_pair(CLIENT_SEED)
    server_private, server_public = _key_pair(SERVER_SEED)

    # Both sides select the same role, so the hash inputs identify their
    # roles incorrectly and the derived keys are not complementary.
    wrong_client = derive_session_keys(
        client_private, server_public, SessionRole.CLIENT
    )
    wrong_server = derive_session_keys(
        server_private, client_public, SessionRole.CLIENT
    )

    assert wrong_client.send != wrong_server.receive
    assert wrong_client.receive != wrong_server.send

    record = SecretBox(wrong_client.send).encrypt(
        b"cannot be received", CLIENT_NONCE
    )
    with pytest.raises(exc.CryptoError):
        SecretBox(wrong_server.receive).decrypt(record)

    correct_client = derive_session_keys(
        client_private, server_public, SessionRole.CLIENT
    )
    wrong_role_client = derive_session_keys(
        client_private, server_public, SessionRole.SERVER
    )
    assert wrong_role_client != correct_client


@pytest.mark.parametrize("invalid_role", ["peer", "CLIENT", "", 0, None])
def test_session_keys_rejects_unknown_role(invalid_role):
    client_private, _ = _key_pair(CLIENT_SEED)
    _, server_public = _key_pair(SERVER_SEED)

    with pytest.raises((exc.TypeError, exc.ValueError)):
        derive_session_keys(client_private, server_public, invalid_role)

    with pytest.raises(exc.ValueError):
        b.crypto_kx_session_keys(
            b.crypto_kx_seed_keypair(CLIENT_SEED)[0],
            b.crypto_kx_seed_keypair(CLIENT_SEED)[1],
            b.crypto_kx_seed_keypair(SERVER_SEED)[0],
            invalid_role,
        )


def test_session_keys_rejects_wrong_peer_public_key():
    client_private, client_public = _key_pair(CLIENT_SEED)
    server_private, server_public = _key_pair(SERVER_SEED)
    _, other_public = _key_pair(OTHER_PEER_SEED)

    correct = derive_session_keys(
        client_private, server_public, SessionRole.CLIENT
    )
    with_other_peer = derive_session_keys(
        client_private, other_public, SessionRole.CLIENT
    )

    assert with_other_peer != correct
    assert with_other_peer.send != correct.send
    assert with_other_peer.receive != correct.receive

    record = SecretBox(with_other_peer.send).encrypt(
        b"wrong peer", CLIENT_NONCE
    )
    with pytest.raises(exc.CryptoError):
        SecretBox(correct.receive).decrypt(record)

    correct_server = derive_session_keys(
        server_private, client_public, SessionRole.SERVER
    )
    server_with_other_peer = derive_session_keys(
        server_private, other_public, SessionRole.SERVER
    )
    assert server_with_other_peer != correct_server
    assert server_with_other_peer.send != correct_server.send
    assert server_with_other_peer.receive != correct_server.receive
    with pytest.raises(exc.CryptoError):
        SecretBox(server_with_other_peer.receive).decrypt(record)


def test_session_keys_validates_key_material():
    client_private, client_public = _key_pair(CLIENT_SEED)
    server_private, server_public = _key_pair(SERVER_SEED)

    with pytest.raises(exc.TypeError):
        derive_session_keys(
            client_private, bytes(server_public)[:-1], SessionRole.CLIENT
        )

    with pytest.raises(exc.ValueError):
        derive_session_keys(
            (server_public, client_private),
            server_public,
            SessionRole.CLIENT,
        )

    with pytest.raises(exc.ValueError):
        b.crypto_kx_session_keys(
            bytes(server_public),
            bytes(client_private),
            bytes(server_public),
            "client",
        )

    with pytest.raises(exc.TypeError):
        derive_session_keys(
            client_public, server_public, SessionRole.CLIENT
        )

    with pytest.raises(exc.TypeError):
        derive_session_keys(
            client_private, server_private, SessionRole.CLIENT
        )
