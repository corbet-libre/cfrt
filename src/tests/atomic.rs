//! Example atomic caller port exercised by real domain verification, not production storage.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Record {
    maximum: u64,
    expires: u64,
    actions: BTreeSet<String>,
}
#[derive(Clone, Default)]
struct AtomicConsumption(Arc<Mutex<BTreeMap<(String, String), Record>>>);
impl Consumption for AtomicConsumption {
    fn reserve(&mut self, proof: &str, usage: &Use<'_>, expires: u64) -> bool {
        let mut records = self.0.lock().unwrap();
        let record = records
            .entry((proof.into(), usage.scope.into()))
            .or_insert_with(|| Record {
                maximum: usage.maximum,
                expires,
                actions: BTreeSet::new(),
            });
        if record.maximum != usage.maximum || record.expires != expires {
            return false;
        }
        if record.actions.contains(usage.action) {
            return true;
        }
        if record.actions.len() as u64 >= record.maximum {
            return false;
        }
        record.actions.insert(usage.action.into());
        true
    }
}

#[test]
fn altcha_concurrent_exact_retries_reserve_one_action_and_reject_changed_context() {
    let engine = signer();
    let now = now();
    let issued = engine.issue(&usage(), work(), now, now + 300).unwrap();
    let solution = altcha::solve_challenge(altcha::SolveChallengeOptions::new(issued.challenge()))
        .unwrap()
        .unwrap();
    let store = AtomicConsumption::default();
    std::thread::scope(|threads| {
        let joins: Vec<_> = (0..8)
            .map(|_| {
                let mut port = store.clone();
                let engine = &engine;
                let issued = &issued;
                let solution = &solution;
                threads.spawn(move || {
                    engine
                        .verify(
                            issued,
                            solution,
                            &usage(),
                            &mut port,
                            Disclosure::Minimal,
                            now,
                        )
                        .is_ok()
                })
            })
            .collect();
        assert!(joins.into_iter().all(|join| join.join().unwrap()));
    });
    let records = store.0.lock().unwrap();
    assert_eq!(records.len(), 1);
    let record = records.values().next().unwrap();
    assert_eq!(record.actions.len(), 1);
    assert_eq!(record.maximum, 3);
    drop(records);
    for changed in [
        Use {
            action: "different-action",
            ..usage()
        },
        Use {
            scope: "different-scope",
            ..usage()
        },
        Use {
            maximum: 4,
            ..usage()
        },
    ] {
        assert!(
            engine
                .verify(
                    &issued,
                    &solution,
                    &changed,
                    &mut store.clone(),
                    Disclosure::Minimal,
                    now
                )
                .is_err()
        );
    }
    assert_eq!(store.0.lock().unwrap().len(), 1);
}

#[test]
fn atomic_port_example_enforces_general_limits_concurrent_actions_and_exact_terms() {
    let store = AtomicConsumption::default();
    let accepted = std::thread::scope(|threads| {
        let joins: Vec<_> = ["a", "b", "c", "d", "e", "f"]
            .into_iter()
            .map(|action| {
                let mut port = store.clone();
                threads.spawn(move || port.reserve("opaque-proof", &Use { action, ..usage() }, 300))
            })
            .collect();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|accepted| *accepted)
            .count()
    });
    assert_eq!(accepted, 3);
    let records = store.0.lock().unwrap();
    let record = records.values().next().unwrap();
    assert_eq!(record.actions.len(), 3);
    let winner = record.actions.first().unwrap().clone();
    drop(records);
    assert!(store.clone().reserve(
        "opaque-proof",
        &Use {
            action: &winner,
            ..usage()
        },
        300
    ));
    assert!(!store.clone().reserve(
        "opaque-proof",
        &Use {
            action: "overflow",
            ..usage()
        },
        300
    ));
    assert!(!store.clone().reserve(
        "opaque-proof",
        &Use {
            maximum: 4,
            ..usage()
        },
        300
    ));
    assert!(!store.clone().reserve("opaque-proof", &usage(), 301));
    assert!(store.clone().reserve(
        "opaque-proof",
        &Use {
            scope: "new-window",
            ..usage()
        },
        300
    ));
}

#[test]
fn malformed_full_length_solution_is_refused_without_panicking() {
    let engine = signer();
    let now = now();
    let issued = engine.issue(&usage(), work(), now, now + 300).unwrap();
    let mut solution =
        altcha::solve_challenge(altcha::SolveChallengeOptions::new(issued.challenge()))
            .unwrap()
            .unwrap();
    solution.derived_key = "z".repeat(64);
    assert!(matches!(
        engine.verify(
            &issued,
            &solution,
            &usage(),
            &mut AtomicConsumption::default(),
            Disclosure::Minimal,
            now
        ),
        Err(Error::Rejected)
    ));
}

struct RefuseDispatch;
impl Consumption for RefuseDispatch {
    fn reserve(&mut self, _: &str, _: &Use<'_>, _: u64) -> bool {
        panic!("usage state must not be called after dispatch refusal")
    }
}
impl DispatchState for RefuseDispatch {
    fn reserve_dispatch(&mut self, _: &Quote) -> bool {
        false
    }
}
struct NeverTransport;
impl turnstile::Transport for NeverTransport {
    async fn send(
        &self,
        _: http::Request<Vec<u8>>,
        _: &Quote,
    ) -> Result<http::Response<Vec<u8>>, Error> {
        panic!("network must not run after dispatch refusal")
    }
}
#[test]
fn turnstile_requires_host_dispatch_reservation_before_provider_or_usage() {
    let adapter = turnstile::Turnstile::new(config(Mode::Production), NeverTransport).unwrap();
    let quote = adapter
        .preview(
            &request(),
            "token",
            Price::AtMost(amount()),
            "explicit fixture".into(),
            250,
            100,
        )
        .unwrap();
    assert!(matches!(
        block_on(adapter.verify(
            &request(),
            "token",
            permit(quote, Mode::Production, "turnstile/account/widget"),
            &mut RefuseDispatch,
            Disclosure::Minimal,
            || 100
        )),
        Err(Error::Cost)
    ));
}

#[derive(Default)]
struct DispatchRecords {
    seen: BTreeSet<String>,
    exposure: u64,
}
#[derive(Clone, Default)]
struct AtomicExecution {
    usage: AtomicConsumption,
    dispatch: Arc<Mutex<DispatchRecords>>,
}
impl Consumption for AtomicExecution {
    fn reserve(&mut self, proof: &str, usage: &Use<'_>, expires: u64) -> bool {
        self.usage.reserve(proof, usage, expires)
    }
}
impl DispatchState for AtomicExecution {
    fn reserve_dispatch(&mut self, quote: &Quote) -> bool {
        let mut state = self.dispatch.lock().unwrap();
        let cost = quote.price.maximum().unwrap();
        if state.seen.contains(&quote.binding)
            || cost.unit != amount().unit
            || state.exposure + cost.atoms > 1
        {
            return false;
        }
        state.exposure += cost.atoms;
        state.seen.insert(quote.binding.clone());
        true
    }
}
#[test]
fn same_turnstile_dispatch_raced_across_instances_is_admitted_once() {
    let state = AtomicExecution::default();
    let accepted = std::thread::scope(|threads| {
        let joins: Vec<_> = (0..8)
            .map(|_| {
                let mut port = state.clone();
                threads.spawn(move || {
                    let adapter =
                        turnstile::Turnstile::new(config(Mode::Production), dummy(good())).unwrap();
                    block_on(adapter.verify(
                        &request(),
                        "inert+token&safe",
                        permit(
                            quote(&adapter),
                            Mode::Production,
                            "turnstile/account/widget",
                        ),
                        &mut port,
                        Disclosure::Minimal,
                        || 100,
                    ))
                    .is_ok()
                })
            })
            .collect();
        joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .filter(|accepted| *accepted)
            .count()
    });
    assert_eq!(accepted, 1);
    assert_eq!(state.dispatch.lock().unwrap().exposure, 1);
    assert_eq!(
        state
            .usage
            .0
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .actions
            .len(),
        1
    );
}
