# commit-reveal

SHA256-based [commit-reveal scheme](https://en.wikipedia.org/wiki/Commitment_scheme)
for fair peer-to-peer verification.

Useful for P2P games (fair dice rolls, secret ballots) and any protocol where one
party must commit to a value before revealing it, without a trusted server.

## Protocol

1. Generator picks a payload and random nonce (32 bytes)
2. Computes commitment = `SHA256(payload || nonce)`
3. Sends commitment hash to peer
4. Peer acknowledges receipt
5. Generator reveals payload and nonce
6. Peer verifies `SHA256(payload || nonce) == commitment`
7. Both accept the payload

## Usage

```rust
use commit_reveal::Commitment;

// Generator: create a commitment
let commitment = Commitment::new(b"secret value");
let hash_to_send = commitment.hash;

// ... send hash to peer, receive ack ...

// Generator: reveal payload and nonce
let payload = &commitment.payload;
let nonce = &commitment.nonce;

// Verifier: check the reveal matches the commitment
assert!(Commitment::verify(&hash_to_send, payload, nonce));
```

## Features

- **`serde`** (default) -- enables `Serialize`/`Deserialize` on `Commitment`

## CI

Woodpecker CI on Codeberg runs `cargo build`, `cargo test`, `cargo clippy`, and `cargo fmt --check` on every push and pull request.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
