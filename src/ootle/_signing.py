"""Signing layer.

Defines the :class:`Signer` Protocol that :class:`OotleWallet` consumes,
the stealth-spend seams :class:`StealthSpendCrypto` and
:class:`StealthSigner`, and :class:`LocalSigner` — the in-process
implementation that wraps an :class:`OotleSecretKey` and satisfies both
:class:`Signer` and :class:`StealthSigner`.

All operations are synchronous — the WASM bridge is sync.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from ootle._crypto import CryptoProvider
    from ootle._types.address import Address
    from ootle._types.keys import OotleSecretKey


class Signer(Protocol):
    """Per-key signing seam used by :class:`ootle.OotleWallet`.

    Implementations are structural — anything with these three methods
    can be ``register``-ed on a wallet.
    """

    def address(self) -> Address:
        """Return the :class:`Address` this signer signs for."""
        ...

    def add_signature(
        self,
        tx_json: str,
        seal_pk: bytes,
        authorizers: Sequence[bytes],
        *,
        crypto: CryptoProvider,
    ) -> str:
        """Add this signer's authorisation to ``tx_json``.

        The signing message commits to ``seal_pk``, the owner public key of
        the *seal* signer (the wallet's default), and to ``authorizers``,
        the public key of every authorizer, this signer's included. Every
        co-signer must sign over the same values or the indexer rejects
        the envelope.

        Returns the updated transaction JSON.
        """
        ...

    def seal(self, tx_json: str, *, crypto: CryptoProvider) -> str:
        """Seal ``tx_json`` with this signer's secret. Returns sealed JSON."""
        ...


class StealthSpendCrypto(Protocol):
    """Crypto surface needed to sign a spent stealth-input UTXO.

    ``stealth_dh_secret`` (a :class:`~ootle._crypto.StealthCryptoProvider`
    method) derives the one-time spend key; ``public_key_from_secret`` and
    ``add_transaction_signer`` (:class:`~ootle._crypto.CryptoProvider`
    methods) give its public key and add its signature. The vendored
    ``WasmCryptoProvider`` satisfies all three.
    """

    def stealth_dh_secret(
        self, network_byte: int, owner_secret: bytes, view_secret: bytes, public_nonce: bytes
    ) -> bytes:
        """Derive the one-time stealth spend scalar ``c + k`` (32 bytes)."""
        ...

    def public_key_from_secret(self, sk: bytes) -> bytes:
        """Return the 32-byte public key of ``sk``."""
        ...

    def add_transaction_signer(
        self, tx_json: str, signer_sk: bytes, seal_pk: bytes, authorizers: Sequence[bytes]
    ) -> str:
        """Add an sr25519 signature from ``signer_sk`` to ``tx_json``."""
        ...


@runtime_checkable
class StealthSigner(Protocol):
    """A :class:`Signer` that can also sign a spent stealth-input UTXO.

    Implementations hold an account secret and derive the per-input
    one-time spend key on demand. ``LocalSigner`` satisfies it; the
    stealth authorizer narrows registered signers to this Protocol
    before asking them to authorise a stealth input.
    """

    def stealth_public_key(self, public_nonce: bytes, *, crypto: StealthSpendCrypto) -> bytes:
        """Return the one-time public key for ``public_nonce``, without signing.

        Every authorization commits to the full authorizer set, so each
        stealth input's key must be known before anyone signs.
        """
        ...

    def add_stealth_signature(
        self,
        tx_json: str,
        public_nonce: bytes,
        seal_pk: bytes,
        authorizers: Sequence[bytes],
        *,
        crypto: StealthSpendCrypto,
    ) -> str:
        """Sign ``tx_json`` with the one-time key for ``public_nonce``."""
        ...


class LocalSigner:
    """A :class:`Signer` backed by an in-memory :class:`OotleSecretKey`.

    The :class:`Address` is computed on first call and cached.
    """

    __slots__ = ("_address_cache", "_secret")

    def __init__(self, secret: OotleSecretKey) -> None:
        self._secret = secret
        self._address_cache: Address | None = None

    def address(self) -> Address:
        """Return the :class:`Address` this signer signs for, cached."""
        if self._address_cache is None:
            self._address_cache = self._secret.to_address()
        return self._address_cache

    def add_signature(
        self,
        tx_json: str,
        seal_pk: bytes,
        authorizers: Sequence[bytes],
        *,
        crypto: CryptoProvider,
    ) -> str:
        """Add an sr25519 signature using the owner secret.

        The signing message commits to ``seal_pk`` (the wallet's seal
        signer) and ``authorizers`` (every authorizer's public key).
        """
        return crypto.add_transaction_signer(
            tx_json, self._secret.owner_secret, seal_pk, authorizers
        )

    def seal(self, tx_json: str, *, crypto: CryptoProvider) -> str:
        """Seal the transaction JSON with the owner secret."""
        return crypto.seal_transaction(tx_json, self._secret.owner_secret)

    def stealth_public_key(self, public_nonce: bytes, *, crypto: StealthSpendCrypto) -> bytes:
        """Return the one-time public key for ``public_nonce``."""
        return crypto.public_key_from_secret(self._one_time_secret(public_nonce, crypto))

    def _one_time_secret(self, public_nonce: bytes, crypto: StealthSpendCrypto) -> bytes:
        return crypto.stealth_dh_secret(
            self._secret.network.value,
            self._secret.owner_secret,
            self._secret.view_secret,
            public_nonce,
        )

    def add_stealth_signature(
        self,
        tx_json: str,
        public_nonce: bytes,
        seal_pk: bytes,
        authorizers: Sequence[bytes],
        *,
        crypto: StealthSpendCrypto,
    ) -> str:
        """Add an sr25519 signature from the one-time stealth spend key.

        Derives the one-time spend scalar ``c + k`` for the stealth UTXO
        whose sender nonce is ``public_nonce`` (``c = H(network || v·R)``
        from this signer's view secret, plus its account secret), then signs ``tx_json``
        with it. Mirrors Rust ``sign_authorization_with_stealth``; the
        derived key's public key is the UTXO's ``SpendAuthorization::Key``
        value, so the engine accepts the spend.

        The signing message commits to ``seal_pk`` (the seal signer's
        owner public key) and ``authorizers``, which must hold the
        one-time key (see :meth:`stealth_public_key`).
        """
        one_time_secret = self._one_time_secret(public_nonce, crypto)
        return crypto.add_transaction_signer(tx_json, one_time_secret, seal_pk, authorizers)
