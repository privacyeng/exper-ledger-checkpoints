# exper ledger checkpoints

This repo is an external, publicly-readable witness for the [exper](https://github.com/privacyeng/exper) app's shared token ledger.

## What's in here

`exper`'s shared token ledger (a Solid Pod resource, dual-signed and append-only) is periodically checkpointed by `support/checkpoint_ledger.py`: every entry's public fields are hashed and folded into a hash chain, signed with a dedicated checkpoint-signing keypair, and committed here as `checkpoint-<YYYY-MM-DD>.ttl`, one file per day, chained to the previous day's checkpoint via `ex:previousCheckpoint`. Files here are never modified or deleted after being committed — this repo's `main` branch is protected (no force-push, no history rewrite) specifically so this history is an independent, tamper-evident record of the ledger's state over time, separate from anything the ledger's own Pod-hosting service account controls.

## Why a public repo

Anyone can clone this repo and independently verify the ledger's integrity without needing any Solid Pod credentials — `curl`ing a raw checkpoint file here, or cloning the full history, works with zero authentication. That's the point: a witness only a small group can read isn't really independent of the thing it's witnessing.

## Verifying

See `support/verify_ledger_checkpoints.py` and `support/verify_receipt.py` in the [exper repo](https://github.com/privacyeng/exper) for tooling that checks a checkpoint's signature and, given a downloaded payment receipt, its Merkle inclusion proof against a checkpoint published here.

## Format

Each `checkpoint-<date>.ttl` is a small Turtle document — see `lib/models/ledger_checkpoint.dart` and `lib/constants/vocab.dart`'s "Ledger checkpoints" section in the exper repo for the exact vocabulary.
