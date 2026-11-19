"""Schema V2 signing against the real blob: authorizations bind the authorizer set."""

from __future__ import annotations

import json
from typing import cast

import pytest

from ootle import LocalSigner, OotleSecretKey, OotleWallet
from ootle._crypto import CryptoProvider
from ootle._transaction_builder import TransactionBuilder
from ootle._types.network import Network
from ootle._types.transaction import TransactionRequest
from ootle.errors import CryptoBridgeError


def _unsigned_json() -> str:
    return TransactionBuilder(Network.LOCAL_NET).with_max_epoch(5).build_unsigned().json


def _signer(crypto: CryptoProvider) -> LocalSigner:
    return LocalSigner(OotleSecretKey.random(Network.LOCAL_NET, crypto=crypto))


def test_add_transaction_signer_refuses_signer_outside_set(crypto: CryptoProvider) -> None:
    sk, _ = crypto.generate_keypair()
    _, other_pk = crypto.generate_keypair()
    with pytest.raises(CryptoBridgeError, match="not among the authorizer"):
        crypto.add_transaction_signer(_unsigned_json(), sk, bytes(32), [other_pk])


def test_authorization_message_commits_to_set(crypto: CryptoProvider) -> None:
    _, pk_a = crypto.generate_keypair()
    _, pk_b = crypto.generate_keypair()
    tx = _unsigned_json()
    one = crypto.hash_unsigned_transaction(tx, bytes(32), [pk_a])
    both = crypto.hash_unsigned_transaction(tx, bytes(32), [pk_a, pk_b])
    assert one != both
    assert both == crypto.hash_unsigned_transaction(tx, bytes(32), [pk_b, pk_a])


def test_wallet_seal_with_external_and_seal_time_cosigners(crypto: CryptoProvider) -> None:
    """An external authorization over the full set folds in beside a seal-time co-signer."""
    seal, cosigner, external = _signer(crypto), _signer(crypto), _signer(crypto)
    wallet = OotleWallet(seal)
    wallet.register(cosigner)
    unsigned = TransactionBuilder(Network.LOCAL_NET).with_max_epoch(5).build_unsigned()
    keys = [cosigner.address().owner_pk, external.address().owner_pk]
    ext_wallet = OotleWallet(seal)
    ext_wallet.register(external)
    auth = ext_wallet.authorize(external.address(), unsigned, authorizers=keys, crypto=crypto)
    request = TransactionRequest().with_transaction(unsigned).add_authorization(auth)
    sealed = cast(
        "dict[str, dict[str, object]]", json.loads(wallet.seal(request, crypto=crypto).json)
    )
    body = cast("dict[str, object]", sealed["V2"]["body"])
    sigs = cast("list[dict[str, str]]", body["signatures"])
    got = [s["public_key"] for s in sigs]
    assert got == sorted(k.hex() for k in keys)
