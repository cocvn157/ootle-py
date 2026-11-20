"""``OotleWallet`` — multi-signer registry.

Holds zero or more :class:`Signer` instances keyed by their
:class:`Address`, tracks a default signer, and exposes ``seal()`` and
``authorize()`` for the signing → sending flow. Sync throughout — the
WASM bridge is sync.
"""

from __future__ import annotations

import logging
from types import MappingProxyType
from typing import TYPE_CHECKING

from ootle._types.transaction import Transaction, TransactionAuthorization, UnsignedTransaction
from ootle._wallet_seal import authorizer_set, seal_request
from ootle.errors import (
    DefaultSignerNotSetError,
    InvalidArgumentError,
    KeyProviderNotFoundError,
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from ootle._crypto import CryptoProvider
    from ootle._signing import Signer
    from ootle._types.address import Address
    from ootle._types.stealth import (
        DecryptedData,
        EncryptedData,
        Output,
        StealthTransferStatement,
    )
    from ootle._types.transaction import TransactionRequest


class OotleWallet:
    """Per-process registry of signers plus a default-signer slot.

    The default signer seals; all other registered signers can be asked
    to ``authorize`` a transaction (returning a
    :class:`TransactionAuthorization`) and have their authorisation
    folded in at seal time.
    """

    __slots__ = ("_crypto", "_default_address", "_signers")

    def __init__(self, default: Signer | None = None, *, crypto: object | None = None) -> None:
        self._signers: dict[Address, Signer] = {}
        self._default_address: Address | None = None
        self._crypto: object | None = crypto
        if default is not None:
            self.register(default)

    def set_crypto(self, crypto: object) -> None:
        """Attach a stealth-capable :class:`CryptoProvider` for read helpers."""
        self._crypto = crypto

    def register(self, signer: Signer) -> None:
        """Add a signer to the registry. Becomes the default if none is set."""
        address = signer.address()
        self._signers[address] = signer
        if self._default_address is None:
            self._default_address = address

    def set_default(self, address: Address) -> None:
        """Switch the default signer.

        Raises:
            KeyProviderNotFoundError: ``address`` is not registered.
        """
        if address not in self._signers:
            raise KeyProviderNotFoundError(
                f"no signer registered for {address.bech32m}", address=address
            )
        self._default_address = address

    @property
    def default_address(self) -> Address:
        """The address of the current default signer.

        Raises:
            DefaultSignerNotSetError: The wallet has no signers registered.
        """
        if self._default_address is None:
            msg = "wallet has no default signer"
            raise DefaultSignerNotSetError(msg)
        return self._default_address

    @property
    def signers(self) -> Mapping[Address, Signer]:
        """Read-only view of the registered signers."""
        return MappingProxyType(self._signers)

    def authorize(
        self,
        address: Address,
        unsigned: UnsignedTransaction,
        *,
        authorizers: Iterable[bytes],
        crypto: CryptoProvider,
    ) -> TransactionAuthorization:
        """Co-sign ``unsigned`` with the signer registered at ``address``.

        The co-signature commits to the wallet's default (seal) signer's
        owner public key and to ``authorizers``: the owner public key of
        every co-signer, ``address``'s included. Every co-signer must sign
        over the same set, and the sealed transaction must carry an
        authorization from each key in it.

        Returns the resulting :class:`TransactionAuthorization`.
        """
        signer = self._signers.get(address)
        if signer is None:
            raise KeyProviderNotFoundError(
                f"no signer registered for {address.bech32m}", address=address
            )
        default = self._require_default()
        seal_pk = default.address().owner_pk
        logger.debug("co-authorizing with signer at %s", address.bech32m)
        keys = authorizer_set(authorizers)
        signed_json = signer.add_signature(unsigned.json, seal_pk, keys, crypto=crypto)
        return TransactionAuthorization(json=signed_json)

    def seal(self, request: TransactionRequest, *, crypto: CryptoProvider) -> Transaction:
        """Apply all authorisations and seal with the default signer.

        Order: every authorisation in ``request.authorizations`` is
        folded into the transaction JSON, then every non-default
        registered signer adds its signature, and finally the default
        signer seals. The authorizer set is the folded authorisations'
        keys plus every non-default signer's, so a co-signer that signed
        earlier must have signed over that same set.
        """
        if request.transaction is None:
            msg = "TransactionRequest.transaction is None — nothing to seal"
            raise InvalidArgumentError(msg)
        default = self._require_default()
        cosigners = [s for a, s in self._signers.items() if a != self._default_address]
        sealed = seal_request(
            default, cosigners, request.transaction, request.authorizations, crypto=crypto
        )
        return Transaction(json=sealed)

    def cosigner_keys(self) -> tuple[bytes, ...]:
        """Owner public keys of the non-default signers :meth:`seal` signs with."""
        return tuple(a.owner_pk for a in self._signers if a != self._default_address)

    def _require_default(self) -> Signer:
        if self._default_address is None:
            msg = "wallet has no default signer"
            raise DefaultSignerNotSetError(msg)
        return self._signers[self._default_address]

    def decrypt_input_data(
        self,
        commitment: bytes,
        encrypted_input: EncryptedData,
        *,
        sender_public_nonce: bytes,
        view_secret: bytes,
        skip_memo: bool = False,
    ) -> DecryptedData:
        """Decrypt the AEAD-encrypted payload of a stealth UTXO.

        ``sender_public_nonce`` is the UTXO's 32-byte sender public nonce;
        the provider derives the AEAD key from its Diffie-Hellman with
        ``view_secret``.
        """
        from ootle._wallet_stealth import decrypt_input_data  # noqa: PLC0415

        return decrypt_input_data(
            self._crypto,
            commitment,
            encrypted_input,
            sender_public_nonce=sender_public_nonce,
            view_secret=view_secret,
            skip_memo=skip_memo,
        )

    def generate_outputs_statement(
        self, specs: Sequence[Output], revealed: int, *, receiver: bytes | None = None
    ) -> StealthTransferStatement:
        """Generate a stealth outputs statement for ``specs`` + revealed amount.

        ``receiver`` is the key authorised to take the revealed output; it
        defaults to the default account key, which seals the transaction.
        """
        from ootle._wallet_stealth import generate_outputs_statement  # noqa: PLC0415

        key = receiver
        if key is None and revealed > 0:
            key = self.default_address.owner_pk
        return generate_outputs_statement(self._crypto, specs, revealed, key)
