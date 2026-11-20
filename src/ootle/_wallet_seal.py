"""Seal-time helpers consumed by :class:`OotleWallet.seal`.

Splice each :class:`TransactionAuthorization`'s signatures into the
unsigned-transaction body. Kept in a sibling module so ``wallet.py``
stays under the project's 200-line ceiling.

Mirrors Rust's ``TransactionRequest::build``: each
:class:`TransactionAuthorization` carries a pre-computed
``TransactionSignature`` (wrapped in the WASM-side
``UnsealedTransactionV1`` JSON shape ``{transaction, signatures}``).
Folding means collecting those signatures and producing an
``UnsealedTransactionV1`` JSON keyed off the original transaction body
— never replacing the body itself.

Since tari-ootle 0.55 (transaction schema V2) every authorization signs
over the full authorizer set, and the mempool rejects an authorization
list that is not strictly ascending by public key, so the fold sorts and
de-duplicates by key.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from ootle._crypto import CryptoProvider
    from ootle._signing import Signer
    from ootle._types.transaction import TransactionAuthorization, UnsignedTransaction

logger = logging.getLogger(__name__)


def seal_request(
    default: Signer,
    cosigners: Sequence[Signer],
    transaction: UnsignedTransaction,
    authorizations: Sequence[TransactionAuthorization],
    *,
    crypto: CryptoProvider,
) -> str:
    """Fold ``authorizations``, co-sign with ``cosigners``, seal with ``default``.

    The authorizer set is the folded authorisations' keys plus every
    co-signer's owner key. Returns the sealed transaction JSON.
    """
    seal_pk = default.address().owner_pk
    tx_json = fold_authorizations(transaction, authorizations)
    keys = authorizer_set(
        authorization_keys(authorizations), (s.address().owner_pk for s in cosigners)
    )
    for signer in cosigners:
        logger.debug("folding signer at %s into seal", signer.address().bech32m)
        tx_json = signer.add_signature(tx_json, seal_pk, keys, crypto=crypto)
    return default.seal(tx_json, crypto=crypto)


def fold_authorizations(
    transaction: UnsignedTransaction,
    authorizations: Sequence[TransactionAuthorization],
) -> str:
    """Splice each authorisation's signatures into ``transaction``.

    Returns ``transaction.json`` unchanged when ``authorizations`` is
    empty so the no-auth path stays a passthrough.
    """
    if not authorizations:
        return transaction.json
    by_key: dict[str, object] = {}
    for auth in authorizations:
        for sig in _extract_signatures(auth.json):
            by_key.setdefault(_signature_key(sig), sig)
    signatures = [by_key[k] for k in sorted(by_key)]
    body: object = json.loads(transaction.json)
    return json.dumps({"transaction": body, "signatures": signatures})


def authorization_keys(authorizations: Sequence[TransactionAuthorization]) -> list[bytes]:
    """Return the public key of every signature in ``authorizations``."""
    return [
        bytes.fromhex(_signature_key(sig))
        for auth in authorizations
        for sig in _extract_signatures(auth.json)
    ]


def authorizer_set(*groups: Iterable[bytes]) -> tuple[bytes, ...]:
    """Union ``groups`` of 32-byte public keys into a sorted, de-duplicated set."""
    return tuple(sorted({key for group in groups for key in group}))


def _signature_key(sig: object) -> str:
    key = cast("dict[str, object]", sig).get("public_key") if isinstance(sig, dict) else None
    if not isinstance(key, str):
        msg = "authorization signature has no public_key"
        raise ValueError(msg)
    return key.lower()


def _extract_signatures(auth_json: str) -> list[object]:
    doc: object = json.loads(auth_json)
    if isinstance(doc, dict):
        sigs = cast("dict[str, object]", doc).get("signatures")
        if isinstance(sigs, list):
            return cast("list[object]", sigs)
    return []
