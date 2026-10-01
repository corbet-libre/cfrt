# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Historical effort reservation: the current v0.4 tree has no assigned home.
- Effort is per action, not a stored membership gate; no API is decided yet.
- A future owner may request established proof-of-work challenges for an action.
- Never accepts money or payment as effort.
- No own cryptographic primitives: established proof-of-work schemes only.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local workstation
  builds; use GHA, Crow as fallback.
