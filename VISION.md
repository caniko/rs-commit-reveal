# commit-reveal vision

A single-purpose Rust library implementing a SHA256 commit-reveal scheme so two
peers can agree on a value nobody can change after the fact, with no trusted
server. It is meant for peer-to-peer games (fair dice rolls, secret ballots) and
any protocol where one side must commit before the other commits back.

## Problem

In a peer-to-peer protocol there is no referee. If one party picks a value and
sends it, they can pick it after seeing what the other party sent, or deny
having chosen it at all. A commitment scheme closes that hole with a hash the
sender cannot back out of: they publish `SHA256(payload || nonce)` first and the
payload plus nonce afterwards.

## Principles

- **One primitive, no policy.** The crate offers `Commitment` with `new` and
  `verify`. Timeouts, forfeiture rules, transport and acknowledgement are the
  caller's protocol; the doc comment states the forfeit rule without
  implementing it.
- **Fresh nonce every time.** A 32-byte random nonce is generated per
  commitment, which is what stops a payload from being guessed or reused across
  sessions.
- **Small surface.** One struct with `payload`, `nonce` and `hash`, one optional
  `serde` feature for sending commitments over the wire, and no dependencies
  beyond `rand` and `sha2`.
- **Dual-licensed and kept in sync.** MIT OR Apache-2.0, with both license files
  required to stay current.

## Scope

In scope: generating commitments, exposing the payload/nonce/hash fields, and
verifying a reveal against a hash, plus serialization when the `serde` feature
is enabled. That is the whole crate.

## Non-goals

- Not a protocol framework. It does not send messages, handle acknowledgements,
  enforce timeouts, or manage flame/forfeit state.
- Not authenticated encryption or a signature scheme; it proves what was
  committed, not who committed it.

## Direction

No roadmap is documented. Recent history is tooling: Simit project
configuration, generated CI workflows, Harbor input migration and GitHub/
Codeberg host normalisation. Published as `commit-reveal` 0.1.1 on crates.io.

## Place in the fleet

Canix runs this repository as a Simit updater target on atlas so its flake and
generated CI follow the fleet. No Canix-owned Cargo manifest currently depends
on `commit-reveal` by name, though Chessbender's design relies on the same
dice-commitment idea.
