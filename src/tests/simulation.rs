use super::*;
use crate::simulation::{Offer, Requirement, Settings};
use cfbk::cost::Outcome;

fn options() -> Settings<'static> {
    Settings {
        required: "pow.altcha",
        order: CostOrder::Configured,
        budget: Amount {
            atoms: 3,
            ..amount()
        },
        max_attempts: 3,
        now: 100,
        expires: 250,
    }
}
fn offer(outcome: Outcome) -> Offer {
    Offer {
        requirement: Requirement::Work(work()),
        outcome,
        price: Price::AtMost(amount()),
        source: "explicit fixture".into(),
        valid_until: 200,
    }
}
#[test]
fn real_work_validation_and_budgeted_fallback_are_deterministic_and_keep_exposure() {
    let result = simulate(
        &usage(),
        vec![offer(Outcome::SafeFailure), offer(Outcome::Success)],
        options(),
    )
    .unwrap();
    assert_eq!(result.outcome, Outcome::Success);
    assert_eq!(result.mechanism, Some("pow.altcha"));
    assert_eq!(result.exposure.atoms, 2);
    assert_eq!(result.attempts, 2);
    assert!(result.stop.is_none());
    assert!(format!("{result:?}").contains("Simulation"));
    for outcome in [Outcome::Pending, Outcome::Uncertain, Outcome::Refused] {
        let result = simulate(
            &usage(),
            vec![offer(outcome), offer(Outcome::Success)],
            options(),
        )
        .unwrap();
        assert_eq!(result.outcome, outcome);
        assert_eq!(result.attempts, 1);
        assert_eq!(result.exposure.atoms, 1);
    }
    let result = simulate(
        &usage(),
        vec![offer(Outcome::SafeFailure), offer(Outcome::Success)],
        Settings {
            budget: amount(),
            ..options()
        },
    )
    .unwrap();
    assert_eq!(result.stop, Some(cfbk::cost::Error::Budget));
    assert_eq!(result.exposure.atoms, 1);
    let result = simulate(&usage(), vec![offer(Outcome::SafeFailure)], options()).unwrap();
    assert_eq!(result.stop, Some(cfbk::cost::Error::Finished));
    let mut unknown = offer(Outcome::Success);
    unknown.price = Price::Unknown;
    assert!(matches!(
        simulate(&usage(), vec![unknown], options()),
        Err(Error::Cost)
    ));
    let mut bad = offer(Outcome::Success);
    bad.requirement = Requirement::Work(pow::Work {
        iterations: 0,
        ..work()
    });
    assert!(matches!(
        simulate(&usage(), vec![bad], options()),
        Err(Error::Configuration)
    ));
    assert!(
        simulate(
            &Use {
                scope: "",
                ..usage()
            },
            vec![offer(Outcome::Success)],
            options()
        )
        .is_err()
    );
}
#[test]
fn simulation_validates_turnstile_and_never_substitutes_an_ineligible_mechanism() {
    let captcha = || Offer {
        requirement: Requirement::Turnstile {
            action: "dummy-action".into(),
            nonce: "dummy-nonce".into(),
        },
        ..offer(Outcome::Success)
    };
    assert!(matches!(
        simulate(&usage(), vec![captcha()], options()),
        Err(Error::Cost)
    ));
    let result = simulate(
        &usage(),
        vec![captcha()],
        Settings {
            required: "captcha.turnstile",
            ..options()
        },
    )
    .unwrap();
    assert_eq!(result.mechanism, Some("captcha.turnstile"));
    let mut cheaper = offer(Outcome::Success);
    cheaper.price = Price::Exact(Amount {
        atoms: 0,
        ..amount()
    });
    let result = simulate(
        &usage(),
        vec![offer(Outcome::Refused), cheaper],
        Settings {
            order: CostOrder::Cheapest,
            ..options()
        },
    )
    .unwrap();
    assert_eq!(result.outcome, Outcome::Success);
    assert_eq!(result.exposure.atoms, 0);
}
