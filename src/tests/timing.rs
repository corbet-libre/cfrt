use super::*;
use crate::extension as work;
use crate::turnstile::Transport as _;
use std::task::Poll;

async fn reply_after_yield(clock: &Cell<u64>, completion: u64) {
    let mut pending = true;
    std::future::poll_fn(|cx| {
        if pending {
            pending = false;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            clock.set(completion);
            Poll::Ready(())
        }
    })
    .await;
}

struct TimedPort<'a> {
    clock: &'a Cell<u64>,
    dispatch_at: u64,
    accepted_at: u64,
    dispatched: usize,
    consumed: usize,
}
impl DispatchState for TimedPort<'_> {
    fn reserve_dispatch(&mut self, _: &Quote) -> bool {
        self.dispatched += 1;
        self.clock.set(self.dispatch_at);
        true
    }
}
impl Consumption for TimedPort<'_> {
    fn reserve(&mut self, _: &str, _: &Use<'_>, _: u64) -> bool {
        self.consumed += 1;
        // Exercise the final guard even when a slow host port reports success.
        self.clock.set(self.accepted_at);
        true
    }
}

struct DelayedTransport<'a> {
    clock: &'a Cell<u64>,
    completed_at: u64,
    sent: &'a Cell<usize>,
}
impl turnstile::Transport for DelayedTransport<'_> {
    async fn send(
        &self,
        request: http::Request<Vec<u8>>,
        quote: &Quote,
    ) -> Result<http::Response<Vec<u8>>, Error> {
        self.sent.set(self.sent.get() + 1);
        let response = dummy(good()).send(request, quote).await?;
        reply_after_yield(self.clock, self.completed_at).await;
        Ok(response)
    }
}

#[test]
fn turnstile_rechecks_time_after_reservation_reply_and_consumption() {
    for (dispatch, completed, accepted, expected, sends, uses) in [
        (99, 100, 100, Some(Error::Cost), 0, 0),
        (250, 260, 260, Some(Error::Cost), 0, 0),
        (300, 300, 300, Some(Error::Cost), 0, 0),
        (100, 99, 99, Some(Error::Rejected), 1, 0),
        (100, 300, 300, Some(Error::Rejected), 1, 0),
        (100, 301, 301, Some(Error::Rejected), 1, 0),
        // A tariff need only be valid at dispatch; it does not shorten the proof.
        (100, 260, 260, None, 1, 1),
        (100, 101, 99, Some(Error::Rejected), 1, 1),
        (100, 101, 300, Some(Error::Rejected), 1, 1),
        (100, 101, 102, None, 1, 1),
    ] {
        for disclosure in [Disclosure::Minimal, Disclosure::Complete] {
            let clock = Cell::new(100);
            let sent = Cell::new(0);
            let adapter = turnstile::Turnstile::new(
                config(Mode::Production),
                DelayedTransport {
                    clock: &clock,
                    completed_at: completed,
                    sent: &sent,
                },
            )
            .unwrap();
            let quote = adapter
                .preview(
                    &request(),
                    "inert+token&safe",
                    Price::AtMost(amount()),
                    "fixture".into(),
                    250,
                    100,
                )
                .unwrap();
            let mut state = TimedPort {
                clock: &clock,
                dispatch_at: dispatch,
                accepted_at: accepted,
                dispatched: 0,
                consumed: 0,
            };
            let result = block_on(adapter.verify(
                &request(),
                "inert+token&safe",
                permit(quote, Mode::Production, "turnstile/account/widget"),
                &mut state,
                disclosure,
                || clock.get(),
            ));
            if let Some(error) = &expected {
                let actual = result.err().expect("late or rolled-back clock must refuse");
                assert_eq!(actual.category(), error);
                assert_eq!(
                    actual.report().is_some(),
                    sends == 1 && disclosure == Disclosure::Complete
                );
                if let Some(report) = actual.report() {
                    assert_eq!(report.information()["status"], 200);
                }
            } else {
                assert!(matches!(
                    result.unwrap(),
                    turnstile::Verified::Production { .. }
                ));
            }
            assert_eq!(sent.get(), sends);
            assert_eq!(state.consumed, uses);
            assert_eq!(
                state.dispatched, 1,
                "expiry never releases admitted exposure"
            );
        }
    }
}

struct DelayedWork<'a> {
    clock: &'a Cell<u64>,
    completed_at: u64,
    sent: &'a Cell<usize>,
    mode: Mode,
}
impl work::Adapter for DelayedWork<'_> {
    fn instance(&self) -> &str {
        "work"
    }
    fn mechanism(&self) -> &'static str {
        "dummy-verified-work"
    }
    fn mode(&self) -> Mode {
        self.mode
    }
    async fn verify(
        &self,
        _: &[u8],
        request: &work::Request<'_>,
        _: &Quote,
    ) -> Result<work::Authenticated, Error> {
        self.sent.set(self.sent.get() + 1);
        reply_after_yield(self.clock, self.completed_at).await;
        Ok(work::Authenticated {
            id: "private-result".into(),
            context: request.binding(),
            expires: 225,
            upstream: serde_json::json!({"private-extension":42}),
        })
    }
}

#[test]
fn useful_work_rechecks_both_request_and_evidence_deadlines_after_await() {
    for (dispatch, completed, accepted, expected, sends, uses) in [
        (99, 100, 100, Some(Error::Cost), 0, 0),
        (240, 240, 240, Some(Error::Cost), 0, 0),
        (300, 300, 300, Some(Error::Cost), 0, 0),
        (100, 99, 99, Some(Error::Rejected), 1, 0),
        (100, 225, 225, Some(Error::Rejected), 1, 0),
        (100, 300, 300, Some(Error::Rejected), 1, 0),
        (100, 101, 99, Some(Error::Rejected), 1, 1),
        (100, 101, 225, Some(Error::Rejected), 1, 1),
        (100, 224, 224, None, 1, 1),
    ] {
        for disclosure in [Disclosure::Minimal, Disclosure::Complete] {
            let clock = Cell::new(100);
            let sent = Cell::new(0);
            let service = work::Service {
                adapter: DelayedWork {
                    clock: &clock,
                    completed_at: completed,
                    sent: &sent,
                    mode: Mode::Production,
                },
            };
            let request = work::Request {
                usage: usage(),
                requirements: &serde_json::Value::Null,
                nonce: "nonce",
                expires: 300,
            };
            let quote = service
                .preview(
                    &request,
                    b"evidence",
                    Price::AtMost(amount()),
                    "fixture".into(),
                    240,
                    100,
                )
                .unwrap();
            let mut state = TimedPort {
                clock: &clock,
                dispatch_at: dispatch,
                accepted_at: accepted,
                dispatched: 0,
                consumed: 0,
            };
            let result = block_on(service.verify(
                &request,
                b"evidence",
                permit(quote, Mode::Production, "work"),
                &mut state,
                disclosure,
                || clock.get(),
            ));
            if let Some(error) = &expected {
                let actual = result.err().expect("late or rolled-back clock must refuse");
                assert_eq!(actual.category(), error);
                assert_eq!(
                    actual.report().is_some(),
                    sends == 1 && disclosure == Disclosure::Complete
                );
                if let Some(report) = actual.report() {
                    assert_eq!(report.information()["private-extension"], 42);
                }
            } else {
                assert!(matches!(result.unwrap(), work::Verified::Production { .. }));
            }
            assert_eq!(sent.get(), sends);
            assert_eq!(state.consumed, uses);
            assert_eq!(state.dispatched, 1);
        }
    }
}

#[test]
fn sandbox_responses_are_also_checked_at_completion() {
    let clock = Cell::new(100);
    let sent = Cell::new(0);
    let adapter = turnstile::Turnstile::new(
        config(Mode::Sandbox),
        DelayedTransport {
            clock: &clock,
            completed_at: 300,
            sent: &sent,
        },
    )
    .unwrap();
    let quote = adapter
        .preview(
            &request(),
            "inert+token&safe",
            Price::Exact(amount()),
            "fixture".into(),
            250,
            100,
        )
        .unwrap();
    let mut state = TimedPort {
        clock: &clock,
        dispatch_at: 100,
        accepted_at: 300,
        dispatched: 0,
        consumed: 0,
    };
    let error = block_on(adapter.verify(
        &request(),
        "inert+token&safe",
        permit(quote, Mode::Sandbox, "turnstile/account/widget"),
        &mut state,
        Disclosure::Complete,
        || clock.get(),
    ))
    .err()
    .unwrap();
    assert_eq!(error.category(), &Error::Rejected);
    assert!(error.report().is_some());
    assert_eq!(state.consumed, 0);

    clock.set(100);
    let service = work::Service {
        adapter: DelayedWork {
            clock: &clock,
            completed_at: 225,
            sent: &sent,
            mode: Mode::Sandbox,
        },
    };
    let request = work::Request {
        usage: usage(),
        requirements: &serde_json::Value::Null,
        nonce: "nonce",
        expires: 300,
    };
    let quote = service
        .preview(
            &request,
            b"evidence",
            Price::AtMost(amount()),
            "fixture".into(),
            240,
            100,
        )
        .unwrap();
    let error = block_on(service.verify(
        &request,
        b"evidence",
        permit(quote, Mode::Sandbox, "work"),
        &mut state,
        Disclosure::Complete,
        || clock.get(),
    ))
    .err()
    .unwrap();
    assert_eq!(error.category(), &Error::Rejected);
    assert!(error.report().is_some());
    assert_eq!(state.consumed, 0);
}
