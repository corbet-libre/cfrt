# cfrt — verified effort

A reusable domain library for requiring verifiable effort for an application
action. The application chooses the mechanism, work factor, scope, deadline and
maximum uses. cfrt verifies it, consumes an opaque proof through a host atomic
port and returns a small proof. It never accepts payment as evidence of effort.

## Working integrations

| Adapter | Upstream | Meaning and limits |
|---|---|---|
| ALTCHA v2 | Official `altcha` Rust library, current compatible 1.x | PBKDF2 search solution under server-signed work requirements. Does not prove human identity, elapsed time or useful application computation. |
| Cloudflare Turnstile | Official Siteverify REST contract; maintained `http`, `serde_urlencoded`, `serde_json` | Provider-approved widget result bound to configured hostname, action and host cData. Does not reveal how much human effort occurred or establish person uniqueness. |

`pow::Altcha::issue` returns an authoritative RAM envelope and signed wire
challenge. Retain the envelope until `verify`; never reconstruct requirements
from member input. Only the challenge is sent to the client. Work is bounded at
issuance; verification uses the official library. Upstream expiration additionally
uses the system wall clock. The host must maintain a trustworthy clock.

For Turnstile, configure a stable account/widget instance, hostname, server
secret and mode. Pass `Request::challenge_data()` as the widget cData, with the
requested widget action. Obtain a pure `preview` from an explicit tariff, construct
a `cfbk::cost::Plan`, then pass its move-only permit to `verify`. Supply an HTTP
transport implementing the documented TLS, no-redirect/no-retry, response-bound
requirements. The supplied state also implements `DispatchState`: the library
requires atomic operation/exposure reservation before calling transport. No
transport is silently configured.

`Consumption::reserve` is a caller-owned atomic operation: proof + scope + action,
maximum uses and expiry. Repeated action IDs are idempotent; different action IDs
count separately; conflicting policy must fail closed. A process-local counter
is suitable only for deterministic tests. ALTCHA's current challenge is also
bound to one action, so increasing its use ceiling does not remove that binding.
This prevents cross-action reuse; other mechanisms may support transferable work.

## Costs, modes and fallback

`local_quote` states zero third-party service fee for local verification. CPU,
hosting and member effort are separate resource costs. Turnstile has no implicit
free price: the operator supplies a sourced, valid exact fee or maximum covering
its contract/tier. `Price::Unknown` is informative and cannot authorize dispatch.
Cost bindings cover account, mode, hostname, action context and token. Request
changes invalidate permission. The required `DispatchState` port reserves cost/execution identity across
processes before transport; cfbk handles the local cascade budget.

Use cfbk configured or cheapest order, selecting only mechanisms the application's
requirements accept. A PoW solution is not an interchangeable biometric proof.
Provider ambiguity is `Error::Uncertain`: retain the quoted maximum exposure and
stop automatic fallback. Provider refusal can still cost its full reserved fee.

`simulate` validates actual work/widget requirements and runs the real cfbk cost
planner/cascade with explicit dummy outcomes. Its `Simulation` carries exposure,
attempts and stops, never a `Proof`, credential, network call or state mutation.
Required capabilities prevent simulation from substituting CAPTCHA for PoW. Turnstile Sandbox accepts only official test
secrets and returns a distinct result that never reserves production usage.
Production rejects those test secrets. No provider sandbox is assumed free.

## Information and credentials

Inputs, secrets, envelopes and results remain RAM-only. No SQL, environment
lookup, database pool, file cache or SDK credential discovery. The host supplies
credentials; stable account instance identity must change when the account or
widget changes, but not on routine secret rotation. ALTCHA uses a separate
random server signing secret of at least 32 bytes. Do not use a phone/email
identity blinding key for it. Secrets have zeroizing owners; upstream ALTCHA and
HTTP serialization create temporary copies that cannot all be guaranteed erased.
Host swap, dumps and transport logging remain host concerns.

Minimal output is normal. `Disclosure::Complete` returns all available upstream
verification fields, including unknown JSON extensions for Turnstile; these are
private transient values without Debug. The caller may explicitly persist what
it requests. Client solve time is untrusted, never part of authenticated effort.
Provider extensions are available information, not extra validated claims.

## Arsenal and extension seams

| Mechanism | Status | Integration considerations |
|---|---|---|
| ALTCHA PBKDF2 | Working | Current official v2 implementation; signed context and bounded work. |
| Turnstile | Working with host transport | Provider test keys separate from production; source contract below. |
| hCaptcha / reCAPTCHA | Candidates | Distinct response semantics and commercial tariffs. hCaptcha hostname is browser-derived, not an authentication boundary. |
| Friendly Captcha / ALTCHA Sentinel | Candidates | Commercial verification and privacy requirements need separate priced adapter contracts. |
| Useful computation / BOINC-style tasks | Trusted `extension::Adapter` service; concrete vendors remain candidates | Need task-owner-authenticated job identity, accepted result verifier, bounded validation, and atomic reward/consumption. Ordinary PoW does not produce useful work by implication. |
| Hardware or specialized proof systems | Candidates | Use a maintained protocol library with explicit verification and resource guarantees; no invented crypto. |

Source contracts checked 2026-10-10:
[ALTCHA Rust](https://github.com/altcha-org/altcha-lib-rs),
[ALTCHA integration](https://altcha.org/docs/integration/server/),
[Turnstile Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/),
[Turnstile test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/),
[hCaptcha](https://docs.hcaptcha.com/).

## Tests

Real ALTCHA challenge/solve/verify with low-cost dummy work; actual HTTP request
construction and provider JSON against inert transport; context, expiry, cost,
mode, malformed/uncertain responses and rich output checks. Integration tests do
not duplicate upstream KDF tests. Crow compiles/tests; no live provider calls,
paid work, credentials or hardware verification have been executed. Hardware and
commercial candidate rows are not implemented adapters.

See [the contract](docs/CONTRACT.md) and [provider notes](docs/PROVIDERS.md).

`extension::Service` makes the adapter model open to further mechanisms. The
adapter must independently authenticate the exact caller requirements, fresh
context, result ID and expiry. The service requires bound cost permission plus
host dispatch reservation, then consumption, and applies minimal/complete and
sandbox separation uniformly. The public `Authenticated` value is a trusted-code
port, not member input or an accepting JSON endpoint.

Complete response access also applies to bounded provider replies that fail a
predicate or atomic consumption. Inspect `Error::report()` explicitly;
`Error::category()` preserves the domain failure used for orchestration. Reports
remain RAM-only, redact Debug/Display, and cannot create a verified proof. Trusted
extension adapters can use `Error::with_report` for their own available errors.
Turnstile also returns exact bounded HTTP status, headers and body bytes in its complete transport report, including non-2xx and malformed replies. Oversized replies are refused without retaining an unbounded payload.
