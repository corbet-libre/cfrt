use super::*;
use crate::extension::{Adapter, Authenticated, Request, Service, Verified};

struct Extension {
    instance: &'static str,
    mechanism: &'static str,
    mode: Mode,
    mutate: fn(&mut Authenticated),
    fail: bool,
}
impl Adapter for Extension {
    fn instance(&self) -> &str {
        self.instance
    }
    fn mechanism(&self) -> &'static str {
        self.mechanism
    }
    fn mode(&self) -> Mode {
        self.mode
    }
    async fn verify(
        &self,
        evidence: &[u8],
        request: &Request<'_>,
        quote: &Quote,
    ) -> Result<Authenticated, Error> {
        assert_eq!(evidence, b"inert-result");
        assert!(!quote.binding.is_empty());
        if self.fail {
            return Err(Error::Uncertain);
        }
        let mut result = Authenticated {
            id: "authenticated-job-result-id".into(),
            context: request.binding(),
            expires: 225,
            upstream: serde_json::json!({"unknown-extension":42}),
        };
        (self.mutate)(&mut result);
        Ok(result)
    }
}
fn service() -> Service<Extension> {
    Service {
        adapter: Extension {
            instance: "job-provider",
            mechanism: "verified-dummy-computation",
            mode: Mode::Production,
            mutate: |_| {},
            fail: false,
        },
    }
}
fn request() -> Request<'static> {
    Request {
        usage: usage(),
        requirements: &serde_json::Value::Null,
        nonce: "dummy-nonce",
        expires: 250,
    }
}
fn quote(svc: &Service<Extension>, request: &Request<'_>) -> Quote {
    svc.preview(
        request,
        b"inert-result",
        Price::AtMost(amount()),
        "explicit fixture".into(),
        240,
        100,
    )
    .unwrap()
}
fn permit(svc: &Service<Extension>, request: &Request<'_>) -> DispatchPermit<String> {
    super::permit(quote(svc, request), svc.adapter.mode(), "job-provider")
}
struct Port {
    dispatch: bool,
    consume: bool,
    dispatched: usize,
    consumed: usize,
}
impl DispatchState for Port {
    fn reserve_dispatch(&mut self, _: &Quote) -> bool {
        self.dispatched += 1;
        self.dispatch
    }
}
impl Consumption for Port {
    fn reserve(&mut self, id: &str, usage: &Use<'_>, expires: u64) -> bool {
        assert_eq!(id.len(), 64);
        assert_eq!(usage.maximum, 3);
        assert_eq!(expires, 225);
        self.consumed += 1;
        self.consume
    }
}
fn state() -> Port {
    Port {
        dispatch: true,
        consume: true,
        dispatched: 0,
        consumed: 0,
    }
}
#[test]
fn open_effort_adapter_enforces_modes_requested_information_and_host_state() {
    for mode in [Mode::Production, Mode::Sandbox] {
        for disclosure in [Disclosure::Minimal, Disclosure::Complete] {
            let mut svc = service();
            svc.adapter.mode = mode;
            let mut port = state();
            let result = block_on(svc.verify(
                &request(),
                b"inert-result",
                permit(&svc, &request()),
                &mut port,
                disclosure,
                100,
            ))
            .unwrap();
            let rich = match result {
                Verified::Production { proof, upstream } => {
                    assert_eq!(proof.mechanism(), "verified-dummy-computation");
                    assert_eq!(proof.expires(), 225);
                    assert_eq!(port.consumed, 1);
                    upstream
                }
                Verified::Sandbox { upstream } => {
                    assert_eq!(port.consumed, 0);
                    upstream
                }
            };
            assert_eq!(port.dispatched, 1);
            assert_eq!(rich.is_some(), disclosure == Disclosure::Complete);
            if let Some(value) = rich {
                assert_eq!(value["unknown-extension"], 42);
            }
        }
    }
    for (dispatch, consume, error) in [
        (false, true, Error::Cost),
        (true, false, Error::Consumption),
    ] {
        let svc = service();
        let mut port = Port {
            dispatch,
            consume,
            ..state()
        };
        let result = block_on(svc.verify(
            &request(),
            b"inert-result",
            permit(&svc, &request()),
            &mut port,
            Disclosure::Minimal,
            100,
        ));
        assert!(matches!(result,Err(actual) if actual == error));
    }
}
#[test]
fn open_effort_adapter_refuses_mismatched_context_invalid_inputs_and_expired_evidence() {
    for mutate in [
        (|r: &mut Authenticated| r.id.clear()) as fn(&mut Authenticated),
        |r| r.context = "wrong".into(),
        |r| r.expires = 100,
    ] {
        let mut svc = service();
        svc.adapter.mutate = mutate;
        assert!(matches!(
            block_on(svc.verify(
                &request(),
                b"inert-result",
                permit(&svc, &request()),
                &mut state(),
                Disclosure::Minimal,
                100
            )),
            Err(Error::Rejected)
        ));
    }
    let mut svc = service();
    svc.adapter.fail = true;
    assert!(matches!(
        block_on(svc.verify(
            &request(),
            b"inert-result",
            permit(&svc, &request()),
            &mut state(),
            Disclosure::Minimal,
            100
        )),
        Err(Error::Uncertain)
    ));
    let svc = service();
    for case in 0..3 {
        let mut q = quote(&svc, &request());
        let mut id = "job-provider";
        let now = if case == 2 { 240 } else { 100 };
        if case == 0 {
            q.binding = "wrong".into();
        } else if case == 1 {
            id = "wrong";
        }
        assert!(matches!(
            block_on(svc.verify(
                &request(),
                b"inert-result",
                super::permit(q, Mode::Production, id),
                &mut state(),
                Disclosure::Minimal,
                now
            )),
            Err(Error::Cost)
        ));
    }
    for case in 0..4 {
        let mut svc = service();
        let evidence = if case == 3 {
            vec![0; 65537]
        } else {
            b"inert-result".to_vec()
        };
        match case {
            0 => svc.adapter.instance = "",
            1 => svc.adapter.mechanism = "",
            2 => svc.adapter.mode = Mode::Simulation,
            _ => {}
        }
        assert!(
            svc.preview(
                &request(),
                &evidence,
                Price::Unknown,
                "source".into(),
                240,
                100
            )
            .is_err()
        );
    }
    let huge = serde_json::Value::String("x".repeat(65537));
    for request in [
        Request {
            nonce: "",
            ..request()
        },
        Request {
            expires: 100,
            ..request()
        },
        Request {
            requirements: &huge,
            ..request()
        },
        Request {
            usage: Use {
                scope: "",
                ..usage()
            },
            ..request()
        },
    ] {
        assert!(
            service()
                .preview(
                    &request,
                    b"inert-result",
                    Price::Unknown,
                    "source".into(),
                    240,
                    100
                )
                .is_err()
        );
    }
    let q = service()
        .preview(
            &request(),
            b"inert-result",
            Price::AtMost(amount()),
            "source".into(),
            300,
            100,
        )
        .unwrap();
    assert_eq!(q.valid_until, 250);
}

#[test]
fn complete_extension_reports_survive_policy_and_consumption_refusal() {
    for rejected in [true, false] {
        let mut svc = service();
        if rejected {
            svc.adapter.mutate = |v| v.context.clear();
        }
        let mut port = state();
        port.consume = false;
        let error = block_on(svc.verify(
            &request(),
            b"inert-result",
            permit(&svc, &request()),
            &mut port,
            Disclosure::Complete,
            100,
        ))
        .err()
        .unwrap();
        assert_eq!(
            error.category(),
            if rejected {
                &Error::Rejected
            } else {
                &Error::Consumption
            }
        );
        assert_eq!(
            error.report().unwrap().information()["unknown-extension"],
            42
        );
    }
}
