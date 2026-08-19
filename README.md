# exper ledger checkpoints

Public, externally-readable witness for the [exper](https://github.com/privacyeng/exper) app's shared token ledger.

## What's here

`checkpoint_ledger.py` (in the exper repo) periodically hashes and chains every ledger entry's public fields, signs the result, and commits it here as `checkpoint-<YYYY-MM-DD>.ttl` — one per day, linked to the previous via `ex:previousCheckpoint`. `token_ledger_checkpoint_latest.ttl` holds the same content under a fixed name, overwritten each run.

`main` is branch-protected — no force-push, no deletion, enforced even for admins — so a committed checkpoint can't be silently rewritten, including by whoever controls the ledger's Pod and signing key. The exper app treats `token_ledger_checkpoint_latest.ttl` **in this repo**, not the Pod's own copy, as authoritative (falling back to the Pod only if this repo is briefly unreachable): the ledger service account can read and write both the ledger and its own checkpoint files, so its copy alone proves nothing.

## Why public

`curl` a checkpoint or clone the full history with no credentials. A witness only a few people can read isn't independent.

## Verifying a receipt

Get `verify_receipt.py` from this repo and a `receipt.json` from the exper app (**My Tokens** → a verified transaction → **Download Receipt** → JSON):

```bash
pip install cryptography
python3 verify_receipt.py --receipt receipt.json
```

Checks, entirely offline, using only the receipt and this script's pinned checkpoint public key:

1. The receipt's transaction hash matches its own fields.
2. Its Merkle proof reconstructs the checkpoint's `merkleRoot`.
3. The checkpoint's signature is genuine.

No exper app, Pod, or network access required.

## Verifying checkpoint history

`support/verify_ledger_checkpoints.py` in the exper repo walks the full checkpoint chain and confirms it end to end — needs Solid credentials, so it isn't published here.

## Format

Each `checkpoint-<date>.ttl` is a small Turtle document — see `lib/models/ledger_checkpoint.dart` / `vocab.dart` in exper for the vocabulary.
