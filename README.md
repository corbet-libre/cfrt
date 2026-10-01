# cfrt

**Reserved per-action effort helper.**

Effort is per action, not a stored gate in the current v0.4 tree. This
reservation has no decided home or API; its historical proof-of-work idea is
not an implemented admission mechanism.

Status: name reserved, no implementation or qualified provider adapter yet.
Empty production coverage is a blocking failure. See
[the current contract](docs/CONTRACT.md).

## Boundaries

What it does:

- Issues effort challenges and verifies client-side effort proofs, for the action that requested the work (unimplemented).

What it never does:

- Never accepts money or payment as effort.
- No own cryptographic primitives: established proof-of-work schemes only.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).

## Continuous verification

Dependency updates follow main and are tested against one CI-resolved lockfile.
Line and branch coverage target 100%; failures remain blocking. See
[the coverage contract](docs/COVERAGE.md) for measurement and exclusions.
