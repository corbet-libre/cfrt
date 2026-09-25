# cfrt

**Effort admission gate for cvld.**

`cfrt` will let a member prove spent effort (proof of work and similar mechanisms) on the client, checked on the server. It rests on us and the member alone, not on a third party.

Status: name reserved, no implementation yet.

## Boundaries

What it does:

- Issues effort challenges and verifies client-side effort proofs, returning an opaque gate proof.

What it never does:

- Never accepts money or payment as effort.
- No own cryptographic primitives: established proof-of-work schemes only.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
