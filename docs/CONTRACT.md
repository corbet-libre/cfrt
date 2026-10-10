# Verified effort contract

Applications select mechanism, requirements, scope, action, deadline and maximum
uses. ALTCHA v2 verifies server-issued PBKDF2 search through the official library;
Turnstile verifies a provider response through its documented Siteverify protocol.
Neither mechanism proves personhood, elapsed effort, payment or useful computation.

The authoritative ALTCHA `Issued` envelope is private, immutable and RAM-only.
Its signed context includes scope/action/maximum; verification refuses changed
terms and uses the original work parameters. The current envelope binds one
action: a higher ceiling does not make work transferable between actions.
Cryptographic processing belongs to upstream. Fixed algorithm, validated work,
generated nonce/salt and immutable envelope make upstream configuration errors
inaccessible to client solutions; malformed full-length solutions are refusal tests.

Turnstile binds account/widget identity, mode, configured hostname, widget action,
fresh cData and token to the preview/permit. Every real call requires a bounded,
sourced, unexpired quote and the required caller `DispatchState` reservation.
That port atomically reserves stable operation identity and total budget before
transport, refuses already-dispatched/uncertain requests, and owns reconciliation
across restarts. `Consumption` separately enforces usage after authentication.
No leaf-owned database, pool, SQL, file cache or hidden persistence exists.

Minimal results are authenticated mechanism/expiry facts. Explicit complete
results relay all available upstream fields in private transient output; arbitrary
provider fields are not extra verified predicates. Production refuses provider
test secrets. Sandbox has distinct output and never reserves production usage.
Deterministic local simulation validates the same requirements and runs cfbk
planning/fallback using dummy outcomes, with a type that cannot become `Proof`.

Host ports own distributed atomicity, idempotent action IDs and policy windows.
Library tests exercise concurrent example ports, changed bindings, privacy,
refusals, uncertainty and cost limits with inert keys and transports. Live
provider/sandbox and hardware flows are unexecuted. See [provider notes](PROVIDERS.md).

`extension::Adapter` integrates additional maintained verifiers without changing
the domain proof type. It authenticates caller-supplied job/work requirements,
full context, result identity and expiry. `extension::Service` validates a bound
quote/permit, requires atomic dispatch, checks authenticated result context and
validity, then reserves usage. Explicit rich and sandbox output preserve the same
boundary as built-ins. A fixture implementation tests this port; it does not
qualify a useful-computation vendor or invent its verification protocol.

Async verification receives a trusted live clock, for example
`verify(..., || trusted_now())`. The library samples it at admission, after
operation reservation, after the provider returns and after atomic consumption.
Clock rollback refuses the operation. Expiry is exclusive: no fresh proof is
returned at or beyond its deadline. Tariff expiry controls dispatch; it does not
invalidate a timely proof from a request already sent under a valid tariff.
Transports must also check a fresh clock immediately before I/O after their own
queue waits. Atomic state ports must check proof validity within their transaction.
Late refusals preserve requested private responses and never automatically undo
committed usage or release potentially billed exposure.
