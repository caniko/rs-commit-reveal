# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Project Overview

`commit-reveal` is a Rust library implementing a SHA256-based commit-reveal scheme for fair peer-to-peer verification without a trusted server. Used in P2P games, secret ballots, and similar protocols.

## Build Commands

```bash
cargo build                  # Build the library
cargo test                   # Run all tests
cargo test <test_name>       # Run a single test (e.g., cargo test verify_single_byte)
cargo doc --open             # Generate and view documentation
```

## Architecture

Single-file library (`src/lib.rs`) with one public struct `Commitment` containing:
- `payload: Vec<u8>` — the committed data
- `nonce: [u8; 32]` — random 32-byte nonce
- `hash: [u8; 32]` — SHA256(payload || nonce)

Two main operations:
- **Commit:** `Commitment::new(payload)` generates nonce and computes hash
- **Verify:** `Commitment::verify(&hash, payload, &nonce)` checks revealed values match the hash

The `serde` feature (enabled by default) adds Serialize/Deserialize to `Commitment` for network transmission.

## Dual License

MIT OR Apache-2.0. Both license files must be kept in sync.
