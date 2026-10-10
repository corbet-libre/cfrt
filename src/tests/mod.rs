use super::*;
use cfbk::cost::{CostOrder, DispatchPermit, Mode, Offer, Plan};
use cfbk::{Candidate, Config};
use futures::executor::block_on;
use std::cell::Cell;

fn usage() -> Use<'static> {
    Use {
        scope: "tenant:epoch",
        action: "opaque-action",
        maximum: 3,
    }
}
struct Store {
    allowed: bool,
    calls: usize,
}
impl Consumption for Store {
    fn reserve(&mut self, key: &str, usage: &Use<'_>, expires: u64) -> bool {
        assert_eq!(key.len(), 64);
        assert!(usage.maximum > 0 && expires > 0);
        self.calls += 1;
        self.allowed
    }
}
fn store() -> Store {
    Store {
        allowed: true,
        calls: 0,
    }
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn work() -> pow::Work {
    pow::Work {
        iterations: 1,
        prefix_digits: 1,
    }
}
fn signer() -> pow::Altcha {
    pow::Altcha::new("inert dummy signing secret only!!".into()).unwrap()
}

#[test]
fn real_upstream_pow_context_expiry_projection_and_consumption() {
    let engine = signer();
    let now = now();
    let issued = engine.issue(&usage(), work(), now, now + 300).unwrap();
    let solution = altcha::solve_challenge(altcha::SolveChallengeOptions::new(issued.challenge()))
        .unwrap()
        .unwrap();
    let mut state = store();
    let full = engine
        .verify(
            &issued,
            &solution,
            &usage(),
            &mut state,
            Disclosure::Complete,
            now,
        )
        .unwrap();
    assert!(full.upstream.unwrap().verified);
    assert_eq!(full.proof.mechanism(), "altcha-v2-pbkdf2");
    assert_eq!(full.proof.expires(), now + 300);
    assert!(format!("{:?}", full.proof).contains("altcha"));
    assert!(
        engine
            .verify(
                &issued,
                &solution,
                &usage(),
                &mut state,
                Disclosure::Minimal,
                now
            )
            .unwrap()
            .upstream
            .is_none()
    );
    state.allowed = false;
    assert!(matches!(
        engine.verify(
            &issued,
            &solution,
            &usage(),
            &mut state,
            Disclosure::Minimal,
            now
        ),
        Err(Error::Consumption)
    ));
    let before = state.calls;
    for changed in [
        Use {
            scope: "other",
            ..usage()
        },
        Use {
            action: "other",
            ..usage()
        },
    ] {
        assert!(matches!(
            engine.verify(
                &issued,
                &solution,
                &changed,
                &mut state,
                Disclosure::Minimal,
                now
            ),
            Err(Error::Rejected)
        ));
    }
    assert!(
        engine
            .verify(
                &issued,
                &solution,
                &usage(),
                &mut state,
                Disclosure::Minimal,
                now + 300
            )
            .is_err()
    );
    let mut bad = solution.clone();
    bad.derived_key = "bad".into();
    assert!(
        engine
            .verify(
                &issued,
                &bad,
                &usage(),
                &mut state,
                Disclosure::Minimal,
                now
            )
            .is_err()
    );
    bad.derived_key = "f".repeat(64);
    assert!(
        engine
            .verify(
                &issued,
                &bad,
                &usage(),
                &mut state,
                Disclosure::Minimal,
                now
            )
            .is_err()
    );
    let other = pow::Altcha::new("different inert dummy signing key!".into()).unwrap();
    assert!(
        other
            .verify(
                &issued,
                &solution,
                &usage(),
                &mut state,
                Disclosure::Minimal,
                now
            )
            .is_err()
    );
    assert_eq!(state.calls, before);
}

#[test]
fn invalid_work_is_rejected_before_computation() {
    assert!(pow::Altcha::new("short".into()).is_err());
    let engine = signer();
    for changed in [
        Use {
            scope: "",
            ..usage()
        },
        Use {
            action: "",
            ..usage()
        },
        Use {
            maximum: 0,
            ..usage()
        },
    ] {
        assert!(engine.issue(&changed, work(), 100, 200).is_err());
    }
    for changed in [
        pow::Work {
            iterations: 0,
            ..work()
        },
        pow::Work {
            iterations: 100001,
            ..work()
        },
        pow::Work {
            prefix_digits: 0,
            ..work()
        },
        pow::Work {
            prefix_digits: 9,
            ..work()
        },
    ] {
        assert!(engine.issue(&usage(), changed, 100, 200).is_err());
    }
    for (now, expires) in [
        (100, 100),
        (100, 4000),
        (i64::MAX as u64, i64::MAX as u64 + 1),
    ] {
        assert!(engine.issue(&usage(), work(), now, expires).is_err());
    }
    assert_eq!(format!("{:?}", Error::Cost), "Cost");
    for error in [
        Error::Configuration,
        Error::Rejected,
        Error::Consumption,
        Error::Uncertain,
        Error::Cost,
    ] {
        assert!(!error.to_string().is_empty());
    }
}

struct Dummy {
    calls: Cell<usize>,
    status: u16,
    body: Vec<u8>,
    fail: bool,
}
impl turnstile::Transport for Dummy {
    async fn send(
        &self,
        request: http::Request<Vec<u8>>,
        quote: &Quote,
    ) -> Result<http::Response<Vec<u8>>, Error> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.uri(),
            "https://challenges.cloudflare.com/turnstile/v0/siteverify"
        );
        assert_eq!(
            request.headers()[http::header::CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        let body: Vec<(String, String)> = serde_urlencoded::from_bytes(request.body()).unwrap();
        assert_eq!(body[1], ("response".into(), "inert+token&safe".into()));
        assert!(quote.price.maximum().is_some());
        if self.fail {
            return Err(Error::Uncertain);
        }
        Ok(http::Response::builder()
            .status(self.status)
            .header("x-provider-extension", "inert-private-header")
            .body(self.body.clone())
            .unwrap())
    }
}
fn request() -> turnstile::Request<'static> {
    turnstile::Request {
        usage: usage(),
        widget_action: "post_1-ok",
        nonce: "opaque-random-nonce",
        expires: 300,
    }
}
fn config(mode: Mode) -> turnstile::Config {
    turnstile::Config {
        instance: "turnstile/account/widget".into(),
        hostname: "example.invalid".into(),
        secret: if mode == Mode::Sandbox {
            "1x0000000000000000000000000000000AA"
        } else {
            "inert+secret&safe"
        }
        .into(),
        mode,
    }
}
fn dummy(value: serde_json::Value) -> Dummy {
    Dummy {
        calls: Cell::new(0),
        status: 200,
        body: serde_json::to_vec(&value).unwrap(),
        fail: false,
    }
}
fn good() -> serde_json::Value {
    serde_json::json!({"success": true, "hostname": "example.invalid", "action": "post_1-ok",
        "cdata": request().challenge_data(), "future-provider-field": {"anything": 7}})
}
fn amount() -> Amount {
    Amount {
        unit: Unit {
            code: "TEST".into(),
            scale: 2,
        },
        atoms: 1,
    }
}
fn permit(quote: Quote, mode: Mode, id: &str) -> DispatchPermit<String> {
    Plan::new(
        vec![Offer {
            candidate: Candidate::new(id.into(), ["effort".to_string()]),
            quote,
        }],
        Config::new([id.into()], ["effort".to_string()]),
        CostOrder::Configured,
        amount(),
        1,
        mode,
        100,
    )
    .unwrap()
    .start()
    .begin(100)
    .unwrap()
}
fn quote(adapter: &turnstile::Turnstile<Dummy>) -> Quote {
    adapter
        .preview(
            &request(),
            "inert+token&safe",
            Price::Exact(amount()),
            "inert fixture tariff".into(),
            250,
            100,
        )
        .unwrap()
}

#[test]
fn provider_verification_modes_rich_output_and_cost_binding() {
    for mode in [Mode::Production, Mode::Sandbox] {
        for disclosure in [Disclosure::Minimal, Disclosure::Complete] {
            let adapter = turnstile::Turnstile::new(config(mode), dummy(good())).unwrap();
            let mut state = store();
            let output = block_on(adapter.verify(
                &request(),
                "inert+token&safe",
                permit(quote(&adapter), mode, "turnstile/account/widget"),
                &mut state,
                disclosure,
                100,
            ))
            .unwrap();
            let upstream = match output {
                turnstile::Verified::Production {
                    proof,
                    upstream,
                    transport,
                } => {
                    assert_eq!(transport.is_some(), disclosure == Disclosure::Complete);
                    assert_eq!(mode, Mode::Production);
                    assert_eq!(proof.mechanism(), "turnstile");
                    assert_eq!(proof.expires(), 300);
                    assert_eq!(state.calls, 1);
                    upstream
                }
                turnstile::Verified::Sandbox {
                    upstream,
                    transport,
                } => {
                    assert_eq!(transport.is_some(), disclosure == Disclosure::Complete);
                    assert_eq!(mode, Mode::Sandbox);
                    assert_eq!(state.calls, 0);
                    upstream
                }
            };
            assert_eq!(upstream.is_some(), disclosure == Disclosure::Complete);
            if let Some(value) = upstream {
                assert_eq!(value["future-provider-field"]["anything"], 7);
            }
        }
    }
    let adapter = turnstile::Turnstile::new(config(Mode::Production), dummy(good())).unwrap();
    for (id, mode, changed) in [
        ("other", Mode::Production, false),
        ("turnstile/account/widget", Mode::Sandbox, false),
        ("turnstile/account/widget", Mode::Production, true),
    ] {
        let mut q = quote(&adapter);
        if changed {
            q.binding = "changed".into();
        }
        assert!(matches!(
            block_on(adapter.verify(
                &request(),
                "inert+token&safe",
                permit(q, mode, id),
                &mut store(),
                Disclosure::Minimal,
                100
            )),
            Err(Error::Cost)
        ));
    }
    assert!(matches!(
        block_on(adapter.verify(
            &request(),
            "inert+token&safe",
            permit(
                quote(&adapter),
                Mode::Production,
                "turnstile/account/widget"
            ),
            &mut Store {
                allowed: false,
                calls: 0
            },
            Disclosure::Minimal,
            100
        )),
        Err(Error::Consumption)
    ));
}

#[test]
fn provider_refusal_ambiguity_and_invalid_requests() {
    for field in ["success", "hostname", "action", "cdata"] {
        let mut value = good();
        value[field] = serde_json::Value::Null;
        let adapter = turnstile::Turnstile::new(config(Mode::Production), dummy(value)).unwrap();
        assert!(matches!(
            block_on(adapter.verify(
                &request(),
                "inert+token&safe",
                permit(
                    quote(&adapter),
                    Mode::Production,
                    "turnstile/account/widget"
                ),
                &mut store(),
                Disclosure::Minimal,
                100
            )),
            Err(Error::Rejected)
        ));
    }
    for (status, body, fail) in [
        (500, vec![], false),
        (200, vec![0; 65537], false),
        (200, b"bad JSON".to_vec(), false),
        (200, vec![], true),
    ] {
        let adapter = turnstile::Turnstile::new(
            config(Mode::Production),
            Dummy {
                calls: Cell::new(0),
                status,
                body,
                fail,
            },
        )
        .unwrap();
        assert!(matches!(
            block_on(adapter.verify(
                &request(),
                "inert+token&safe",
                permit(
                    quote(&adapter),
                    Mode::Production,
                    "turnstile/account/widget"
                ),
                &mut store(),
                Disclosure::Minimal,
                100
            )),
            Err(Error::Uncertain)
        ));
    }
    let adapter = turnstile::Turnstile::new(config(Mode::Production), dummy(good())).unwrap();
    for token in ["".into(), "x".repeat(2049)] {
        assert!(
            adapter
                .preview(
                    &request(),
                    &token,
                    Price::Unknown,
                    "source".into(),
                    250,
                    100
                )
                .is_err()
        );
        assert!(
            block_on(adapter.verify(
                &request(),
                &token,
                permit(
                    quote(&adapter),
                    Mode::Production,
                    "turnstile/account/widget"
                ),
                &mut store(),
                Disclosure::Minimal,
                100
            ))
            .is_err()
        );
    }
    for changed in [
        turnstile::Request {
            widget_action: "",
            ..request()
        },
        turnstile::Request {
            widget_action: "bad!",
            ..request()
        },
        turnstile::Request {
            widget_action: "123456789012345678901234567890123",
            ..request()
        },
        turnstile::Request {
            nonce: "",
            ..request()
        },
        turnstile::Request {
            nonce: &"x".repeat(256),
            ..request()
        },
        turnstile::Request {
            expires: 100,
            ..request()
        },
        turnstile::Request {
            expires: 401,
            ..request()
        },
    ] {
        assert!(
            adapter
                .preview(&changed, "token", Price::Unknown, "source".into(), 250, 100)
                .is_err()
        );
    }
    let q = local_quote(amount().unit, "local-operation".into(), 200);
    assert_eq!(q.price.maximum().unwrap().atoms, 0);
}

#[test]
fn configuration_requires_correct_credential_mode() {
    for changed in [
        turnstile::Config {
            instance: "".into(),
            ..config(Mode::Production)
        },
        turnstile::Config {
            hostname: "".into(),
            ..config(Mode::Production)
        },
        turnstile::Config {
            secret: "".into(),
            ..config(Mode::Production)
        },
        config(Mode::Simulation),
        turnstile::Config {
            mode: Mode::Production,
            ..config(Mode::Sandbox)
        },
        turnstile::Config {
            mode: Mode::Sandbox,
            ..config(Mode::Production)
        },
    ] {
        assert!(turnstile::Turnstile::new(changed, dummy(good())).is_err());
    }
}

mod atomic;

mod simulation;

impl DispatchState for Store {
    fn reserve_dispatch(&mut self, quote: &Quote) -> bool {
        assert!(!quote.binding.is_empty());
        true // Each independent fixture models a newly admitted host operation.
    }
}

mod extension;

#[test]
fn complete_failure_reports_preserve_http_bytes_without_diagnostic_leaks() {
    for (status, body, allowed, category) in [
        (
            500,
            b"private invalid upstream".to_vec(),
            true,
            Error::Uncertain,
        ),
        (
            200,
            b"private invalid upstream".to_vec(),
            true,
            Error::Uncertain,
        ),
        (
            200,
            br#"{"success":false,"future":"private upstream"}"#.to_vec(),
            true,
            Error::Rejected,
        ),
        (
            200,
            serde_json::to_vec(&good()).unwrap(),
            false,
            Error::Consumption,
        ),
    ] {
        let adapter = turnstile::Turnstile::new(
            config(Mode::Production),
            Dummy {
                calls: Cell::new(0),
                status,
                body: body.clone(),
                fail: false,
            },
        )
        .unwrap();
        let error = block_on(adapter.verify(
            &request(),
            "inert+token&safe",
            permit(
                quote(&adapter),
                Mode::Production,
                "turnstile/account/widget",
            ),
            &mut Store { allowed, calls: 0 },
            Disclosure::Complete,
            100,
        ))
        .err()
        .unwrap();
        assert_eq!(error.category(), &category);
        assert_eq!(error.to_string(), category.to_string());
        let report = error.report().unwrap();
        assert_eq!(report.information()["status"], status);
        assert_eq!(report.information()["body"], serde_json::json!(body));
        assert_eq!(
            report.information()["headers"][0][0],
            "x-provider-extension"
        );
        assert!(!format!("{error:?}").contains("private upstream"));
        assert_eq!(format!("{report:?}"), "ProviderReport([redacted])");
    }
    assert!(Error::Uncertain.report().is_none());
    assert_eq!(Error::Cost.category(), &Error::Cost);
}
