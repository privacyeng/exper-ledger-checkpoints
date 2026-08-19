#!/usr/bin/env python3
"""Standalone, fully offline verifier for an exper token-payment receipt
(the JSON blob embedded as a QR code in the PDF receipt, or downloaded
directly as `.json` — see `lib/models/receipt_data.dart`'s `toJson` and
`TokenWalletScreen._downloadReceipt`).

This file is deliberately **self-contained** — no imports from this
repo's other `support/*.py` modules, no `sys.path` tricks, just the
Python standard library plus `cryptography`. That's so it can be handed
to, or published for, someone with no access to (and no need to trust)
the private `exper` app repo at all: they only need this one file plus a
receipt to verify, and never touch GitHub, Solid, or any network call at
runtime. It's synced verbatim into the public
`privacyeng/exper-ledger-checkpoints` witness repo — see
`support/checkpoint.mk`'s `push-verify-receipt` rule — specifically so an
independent third party can get both the checkpoint data and the tool to
check it from the one already-trusted, publicly-readable source.

Needs no Solid credentials, no Pod access, and no network access at all —
everything required to check a receipt's three independent claims is
either in the receipt itself or baked into this script:

  1. The receipt's own `entryHash` is recomputed from its public fields
     (id, payer, payee, status, createdDateTime, amount/encryptedPayload,
     refundsTransactionId, signatures) and compared to the claimed value
     — confirms the receipt wasn't hand-edited.
  2. The receipt's `merkleProof` (audit path) is walked to reconstruct a
     Merkle root, compared to the receipt's own `checkpoint.merkleRoot`
     — confirms `entryHash` is genuinely included in that checkpoint's
     tree, not just a bare unrelated claim sitting next to it.
  3. `checkpoint.signature` is verified against the *pinned*
     checkpoint-signing public key (the same constant as
     `checkpointSigningPublicKeyBase64` in `lib/constants/app.dart`) —
     confirms the checkpoint itself was genuinely produced by
     `checkpoint_ledger.py`, not fabricated to match a forged receipt.

All three must pass for the receipt to be considered genuine. The one
unavoidable trust bootstrap is obtaining *this script* — specifically,
confirming the copy you're running has the genuine pinned public key
below and hasn't otherwise been tampered with — out-of-band, exactly like
trusting a TLS root CA. Fetching it from the branch-protected witness
repo (rather than, say, an email attachment) is what makes that
reasonable: nobody, including whoever controls the ledger service
account's Pod and the checkpoint signing key, can silently rewrite what's
already been pushed there.

The public key itself being embedded in source code openly readable by
anyone is *not* a weakness — that's the whole point of asymmetric
cryptography: publishing a public key can never help anyone forge a
signature, only the private key (which never appears in this repo at
all — see `support/checkpoint_signing_key.json`, gitignored) can do that.

Usage:
    pip install cryptography

    python3 verify_receipt.py --receipt receipt.json
    # Or pipe the QR code's decoded text in directly:
    cat receipt.json | python3 verify_receipt.py --receipt -

Exit code 0 if all three checks pass, 1 otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Must match `checkpointSigningPublicKeyBase64` in lib/constants/app.dart
# exactly — see module docstring for why this is pinned here rather than
# trusted from the receipt itself.
PINNED_CHECKPOINT_PUBLIC_KEY_BASE64 = "sILHSTnosrBuZI5v3lF6RwhhNqlQCqzoajAsrKfm6jI="


class VerificationError(Exception):
    pass


# ── Inlined from support/_ledger_hash.py ────────────────────────────────
#
# Kept as an exact copy (not imported) so this file has zero dependencies
# on the rest of this repo — see module docstring. If
# `lib/utils/ledger_entry_hash.dart` / `support/_ledger_hash.py` ever
# change what's hashed, this copy needs updating too;
# `support/tests/test_verify_receipt.py` golden-vectors would catch drift.

# Same U+001F Unit Separator as `token_canonical.dart`/`ledger_entry_hash.dart`.
_FIELD_SEPARATOR = "\x1f"


def _ledger_entry_hash_bytes(
    *,
    id: str,
    payer_web_id: str,
    payee_web_id: str,
    status: str,
    created_date_time: str,
    amount: Optional[int] = None,
    encrypted_payload: Optional[str] = None,
    refunds_transaction_id: Optional[str] = None,
    payer_signature: Optional[str] = None,
    payee_signature: str,
) -> bytes:
    fields = [
        id,
        payer_web_id,
        payee_web_id,
        status,
        created_date_time,
        str(amount) if amount is not None else "",
        encrypted_payload or "",
        refunds_transaction_id or "",
        payer_signature or "",
        payee_signature,
    ]
    return _FIELD_SEPARATOR.join(fields).encode("utf-8")


def _ledger_entry_hash(
    *,
    id: str,
    payer_web_id: str,
    payee_web_id: str,
    status: str,
    created_date_time: str,
    amount: Optional[int] = None,
    encrypted_payload: Optional[str] = None,
    refunds_transaction_id: Optional[str] = None,
    payer_signature: Optional[str] = None,
    payee_signature: str,
) -> str:
    digest = hashlib.sha256(
        _ledger_entry_hash_bytes(
            id=id,
            payer_web_id=payer_web_id,
            payee_web_id=payee_web_id,
            status=status,
            created_date_time=created_date_time,
            amount=amount,
            encrypted_payload=encrypted_payload,
            refunds_transaction_id=refunds_transaction_id,
            payer_signature=payer_signature,
            payee_signature=payee_signature,
        )
    ).digest()
    return base64.b64encode(digest).decode()


# ── Inlined from support/_merkle.py ─────────────────────────────────────
#
# Only the "reconstruct a root from one leaf + its audit path" direction
# is needed here — this script never builds a tree from scratch, only
# ever verifies a proof against one. See that file for the full
# RFC 6962 implementation (leaf/tree construction too).

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE_PREFIX + left + right).digest()


def _split_point(n: int) -> int:
    """Largest power of two strictly less than `n` (requires n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root_from_audit_path(
    *, leaf_data_hash: bytes, leaf_index: int, tree_size: int, audit_path: List[bytes]
) -> bytes:
    """Reconstructs the Merkle root from `leaf_data_hash` (the target
    entry's own raw entry hash — NOT yet leaf-prefixed) plus its
    `audit_path` — mirrors `rootFromAuditPath` in `merkle_tree.dart`
    exactly. Never needs the other leaves' data."""
    if tree_size < 1 or leaf_index < 0 or leaf_index >= tree_size:
        raise IndexError(f"leaf_index {leaf_index} out of range for tree_size {tree_size}")
    leaf_hash_applied = _leaf_hash(leaf_data_hash)
    return _root_from_path(leaf_index, tree_size, leaf_hash_applied, audit_path)


def _root_from_path(m: int, n: int, leaf_hash_applied: bytes, path: List[bytes]) -> bytes:
    if n == 1:
        return leaf_hash_applied
    k = _split_point(n)
    sibling_for_this_level = path[-1]
    deeper_path = path[:-1]
    if m < k:
        sub_root = _root_from_path(m, k, leaf_hash_applied, deeper_path)
        return _node_hash(sub_root, sibling_for_this_level)
    else:
        sub_root = _root_from_path(m - k, n - k, leaf_hash_applied, deeper_path)
        return _node_hash(sibling_for_this_level, sub_root)


# ── Inlined from support/_checkpoint_canonical.py ───────────────────────

def _canonical_checkpoint_bytes(
    *,
    checkpoint_date: str,
    entry_count: int,
    chain_head_base64: str,
    previous_checkpoint_url: Optional[str] = None,
    merkle_root_base64: Optional[str] = None,
) -> bytes:
    fields = [checkpoint_date, str(entry_count), chain_head_base64]
    if previous_checkpoint_url is not None:
        fields.append(previous_checkpoint_url)
    if merkle_root_base64 is not None:
        fields.append(merkle_root_base64)
    return _FIELD_SEPARATOR.join(fields).encode("utf-8")


# ── Verification ─────────────────────────────────────────────────────────

def verify_receipt(receipt: dict, *, checkpoint_public_key_base64: str) -> None:
    """Raises `VerificationError` on the first check that fails; returns
    normally if the receipt passes all three checks."""
    required = ["txId", "payerWebId", "payeeWebId", "status", "createdDateTime",
                "payeeSignature", "entryHash", "merkleProof", "checkpoint"]
    missing = [k for k in required if k not in receipt]
    if missing:
        raise VerificationError(f"Receipt is missing required field(s): {missing}")

    # ── 1. entryHash recomputation ──────────────────────────────────────
    recomputed_hash = _ledger_entry_hash(
        id=receipt["txId"],
        payer_web_id=receipt["payerWebId"],
        payee_web_id=receipt["payeeWebId"],
        status=receipt["status"],
        created_date_time=receipt["createdDateTime"],
        amount=receipt.get("amount") if receipt.get("encryptedPayload") is None else None,
        encrypted_payload=receipt.get("encryptedPayload"),
        refunds_transaction_id=receipt.get("refundsTransactionId"),
        payer_signature=receipt.get("payerSignature"),
        payee_signature=receipt["payeeSignature"],
    )
    if recomputed_hash != receipt["entryHash"]:
        raise VerificationError(
            f"entryHash mismatch: receipt claims {receipt['entryHash']!r}, "
            f"recomputed {recomputed_hash!r} — the receipt's fields don't "
            "match its own claimed hash (hand-edited or corrupted)."
        )
    print(f"  [1/3] OK  transaction hash recomputes claimed hash: {recomputed_hash}")

    # ── 2. Merkle inclusion proof ────────────────────────────────────────
    proof = receipt["merkleProof"]
    checkpoint = receipt["checkpoint"]
    merkle_root = checkpoint.get("merkleRoot")
    if not merkle_root:
        raise VerificationError("Receipt's checkpoint has no merkleRoot to verify against.")

    reconstructed_root = _root_from_audit_path(
        leaf_data_hash=base64.b64decode(receipt["entryHash"]),
        leaf_index=proof["leafIndex"],
        tree_size=proof["treeSize"],
        audit_path=[base64.b64decode(h) for h in proof["siblingHashes"]],
    )
    if base64.b64encode(reconstructed_root).decode() != merkle_root:
        raise VerificationError(
            "Merkle inclusion proof does NOT reconstruct the checkpoint's "
            "claimed merkleRoot — this entry is not genuinely included in "
            "that checkpoint's tree."
        )
    print(f"  [2/3] OK  Merkle proof reconstructs the public checkpoint merkleRoot: {merkle_root}")

    # ── 3. Checkpoint signature ──────────────────────────────────────────
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(checkpoint_public_key_base64))
    except Exception as e:
        raise VerificationError(f"Could not parse the pinned checkpoint public key: {e}")

    bytes_signed = _canonical_checkpoint_bytes(
        checkpoint_date=checkpoint["checkpointDate"],
        entry_count=checkpoint["entryCount"],
        chain_head_base64=checkpoint["chainHead"],
        previous_checkpoint_url=checkpoint.get("previousCheckpoint"),
        merkle_root_base64=checkpoint.get("merkleRoot"),
    )
    try:
        public_key.verify(base64.b64decode(checkpoint["signature"]), bytes_signed)
    except InvalidSignature:
        raise VerificationError(
            "Checkpoint signature is INVALID against the pinned checkpoint "
            "public key — this checkpoint (and therefore this receipt) was "
            "not genuinely produced by the real checkpoint_ledger.py."
        )
    print(f"  [3/3] OK  Checkpoint signature verifies against the pinned public key "
          f"(signerKeyId={checkpoint.get('signerKeyId')})")


def _parse_json_prefix(content: str) -> dict:
    """Parses the *first* complete JSON value in [content] and ignores
    anything after it, unlike plain `json.loads` (which demands the whole
    string be consumed and raises "Extra data" otherwise). Receipt files
    are single-line JSON with no meaningful trailing content by
    construction, but real-world copies routinely pick up trailing
    whitespace or stray characters that aren't part of the receipt at all
    — e.g. a shell's "missing final newline" marker (zsh prints a bare
    `%`) captured when a receipt was copy-pasted from a terminal instead
    of saved as a raw file. None of that is part of what's cryptographically
    verified below, so it's not worth failing over."""
    return json.JSONDecoder().raw_decode(content.lstrip())[0]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--receipt", type=str, required=True,
                        help="Path to the receipt JSON file, or '-' to read from stdin "
                        "(e.g. piped from a QR code decoder)")
    parser.add_argument("--checkpoint-public-key", default=PINNED_CHECKPOINT_PUBLIC_KEY_BASE64,
                        help="Base64 Ed25519 public key to verify the checkpoint signature "
                        "against (default: the key pinned in this script, matching "
                        "checkpointSigningPublicKeyBase64 in lib/constants/app.dart)")
    args = parser.parse_args()

    try:
        if args.receipt == "-":
            content = sys.stdin.read()
        else:
            content = Path(args.receipt).read_text(encoding="utf-8")
        receipt = _parse_json_prefix(content)
    except (OSError, json.JSONDecodeError) as e:
        print(f"\nERROR: could not read/parse receipt: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Verifying receipt for transaction {receipt.get('txId', '?')} ...")
    try:
        verify_receipt(receipt, checkpoint_public_key_base64=args.checkpoint_public_key)
        print("\nReceipt is GENUINE — all three checks passed.")
    except VerificationError as e:
        print(f"\nFAILED: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
