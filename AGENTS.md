# Agent instructions

Write comments and documentation in English. This is a reusable verified-effort
library; cvld is one consumer. The application defines effort requirements,
usage counts and persistence. No direct databases or hidden file persistence.
Prefer maintained upstream implementations; owned Rust forbids unsafe code.

ALTCHA proof of work, CAPTCHA and useful computation are distinct mechanisms.
Do not infer human uniqueness, elapsed effort, monetary value or useful output
from an unrelated mechanism. Do not invent a work protocol or cryptography.
Every provider request requires a bound cost permit and caller-owned atomic
operation/exposure reservation. Simulation cannot mint production evidence.
No paid, live sandbox or hardware calls without separate explicit authorization.

Format locally; compile/test on Crow from committed candidates. Preserve fmt,
strict Clippy, native tests, Wasm compatibility and complete source coverage.
Use compatible dependency ranges and first-party main, never exact manifest pins.
LGPL-3.0-only WITH LGPL-3.0-linking-exception; no incompatible implementation code.
