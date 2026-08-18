# exper ledger checkpoints

This repo is an external, publicly-readable witness for the [exper](https://github.com/privacyeng/exper) app's shared token ledger.

## What's in here

`exper`'s shared token ledger (a Solid Pod resource, dual-signed and append-only) is periodically checkpointed by `support/checkpoint_ledger.py`: every entry's public fields are hashed and folded into a hash chain, signed with a dedicated checkpoint-signing keypair, and committed here as `checkpoint-<YYYY-MM-DD>.ttl`, one file per day, chained to the previous day's checkpoint via `ex:previousCheckpoint`. Each run also overwrites `token_ledger_checkpoint_latest.ttl` with the same content, so a fetcher that just wants the current state doesn't need to know today's date — overwriting this one file is safe under branch protection (that setting blocks force-pushes and branch deletion, not ordinary forward commits), so every previous version of "latest" stays fully recoverable from git history regardless. The dated files are never modified or deleted after being committed — this repo's `main` branch is protected (no force-push, no history rewrite, enforced even for admins) specifically so this history is an independent, tamper-evident record of the ledger's state over time, separate from anything the ledger's own Pod-hosting service account controls.

The exper app itself treats `token_ledger_checkpoint_latest.ttl` **in this repo** as the authoritative source for its in-app verification badge — it only falls back to the ledger service account's own Pod copy if this repo is briefly unreachable. That's deliberate: the ledger service account can read and write both the ledger and its own Pod-hosted checkpoint files, so on its own that copy can't prove anything wasn't forged. This repo's branch protection is what actually makes a checkpoint tamper-evident.

## Why a public repo

Anyone can clone this repo and independently verify the ledger's integrity without needing any Solid Pod credentials — `curl`ing a raw checkpoint file here, or cloning the full history, works with zero authentication. That's the point: a witness only a small group can read isn't really independent of the thing it's witnessing.

## Verifying

See `support/verify_ledger_checkpoints.py` and `support/verify_receipt.py` in the [exper repo](https://github.com/privacyeng/exper) for tooling that checks a checkpoint's signature and, given a downloaded payment receipt, its Merkle inclusion proof against a checkpoint published here.

## Format

Each `checkpoint-<date>.ttl` is a small Turtle document — see `lib/models/ledger_checkpoint.dart` and `lib/constants/vocab.dart`'s "Ledger checkpoints" section in the exper repo for the exact vocabulary.
