# Effort providers and operational inputs

| Integration | Implemented | Credentials and cost basis |
|---|---|---|
| Official ALTCHA v2 Rust | Signed bounded PBKDF2 challenge, real verification, private complete result | Caller injects random signing secret >=32 bytes; local verification has no third-party fee. CPU/hosting/member work are separate resources. |
| Cloudflare Turnstile | Siteverify form request, authenticated transport, response/context validation and rich JSON | Explicit server secret, hostname and stable account/widget instance. Operator supplies exact or maximum tariff for its contract; no implicit free tier. |
| hCaptcha, reCAPTCHA, Friendly Captcha, ALTCHA Sentinel | Candidates only | Need independent protocol/cost/mode integration; no adapter is claimed here. |
| Useful computation | Working authenticated extension service; concrete vendor adapter not implemented | Task owner must authenticate a job/result verifier and usage semantics. Ordinary PoW is not useful computation by implication. |

The [official ALTCHA library](https://github.com/altcha-org/altcha-lib-rs)
provides the cryptography and protocol. Current compatible ranges and the
committed lock identify tested dependencies; no local KDF or nonce protocol is
invented. Its expiration verifier also checks the system wall clock.

[Turnstile Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
requires server validation of one-use tokens. The transport must authenticate
TLS, bound responses while reading (64 KiB after decompression), and disable
redirects, implicit retry, persistence and request logging. It receives a quote
after the required atomic host reservation. A transport failure or malformed
provider response is uncertain, retaining fee exposure rather than authorizing
another attempt. Provider refusal may still cost the reserved amount.

[Official test secrets](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
are accepted only in explicit Sandbox mode; production rejects them. Sandbox
cost is never presumed zero. No calls using those keys were executed. Configured
provider prices must identify revision/source, denomination, upper bound and
expiry and must cover all charged components. Price discovery itself is not
performed by these adapters.

Credentials, proof inputs and upstream results stay in RAM. Stable identities
are distinct from rotatable provider credentials. Zeroizing secret owners do
not guarantee erasure of copies in upstream serialization, host swap or dumps.
The caller may persist only explicitly requested output; no generic raw journal
or database connection is accepted by the library.

Simulation supplies dummy outcomes and validates real domain requirements,
capabilities and shared cfbk ordering/budget/stop behavior. Its outputs cannot be used as production evidence. Integration tests use real upstream libraries,
inert fixtures and caller-state examples; no external-account signup, spending,
live verification or production qualification is implied.


## Candidate arsenal (reviewed 2026-10-10)

These are integration directions, not installed providers. Account selection,
accepted guarantees, tariffs and activation remain caller choices. Prefer the
upstream implementation; a catalogue row alone is never an authenticated adapter.

| Candidate and primary reference | Reusable work and required inputs | Cost/guarantee boundary |
|---|---|---|
| [mCaptcha / libmcaptcha](https://github.com/mCaptcha/libmcaptcha) | Rust PoW core; integrate its challenge and verification contracts through the effort extension port. | Self-hosting/CPU costs are distinct from third-party fees. Review current maintenance, license and replay model before adoption. |
| [hCaptcha](https://docs.hcaptcha.com/) | Siteverify protocol; explicit sitekey/server secret and authenticated token response. | Account tariff and charged attempts require bounds. CAPTCHA does not prove biometric identity or a fixed amount of human labor. |
| [reCAPTCHA](https://developers.google.com/recaptcha/docs/verify) | Server token verification; trusted site/account secret, exact product/version and expected context. | Product-specific response meaning matters; do not reinterpret a score-only response as a measured effort quantity. |
| [Friendly Captcha v2](https://developer.friendlycaptcha.com/docs/v2/api) | Siteverify HTTP integration with explicit API key and selected endpoint. | Contract-based service fee and compute burden are separate. Integrate real failure/mode semantics rather than assume protocol compatibility. |
| [BOINC validation](https://github.com/BOINC/boinc/wiki/ValidationIntro) | Established project/application result validators; authenticate the completed job and exact assigned work through `extension::Adapter`. | A task-specific validator is essential. Ordinary participation or reported runtime is not proof of useful work. External project storage stays outside this RAM-only library. |

ALTCHA and Turnstile are the concrete integrations above. The open extension
service can enforce request/expiry/cost/consumption around a trusted useful-work
verifier, but no BOINC job is launched or credited by this implementation.
