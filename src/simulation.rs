//! Deterministic domain validation and cost cascades, without providers or production proofs.
use crate::{Error, Use, pow, turnstile};
use cfbk::cost::{Amount, CostOrder, Mode, Offer as CostOffer, Outcome, Plan, Price, Quote};
use cfbk::{Candidate, Config};

/// Explicit dummy mechanism requirements. Validation is shared with real dispatch.
pub enum Requirement {
    /// The maintained ALTCHA integration's bounded work requirements.
    Work(pow::Work),
    /// The real Turnstile request's widget parameters, with an inert nonce.
    Turnstile {
        /// Dummy widget action.
        action: String,
        /// Dummy opaque challenge nonce.
        nonce: String,
    },
}
impl Requirement {
    fn capability(&self) -> &'static str {
        match self {
            Self::Work(_) => "pow.altcha",
            Self::Turnstile { .. } => "captcha.turnstile",
        }
    }
    fn validate(&self, usage: &Use<'_>, now: u64, expires: u64) -> Result<(), Error> {
        usage.validate()?;
        match self {
            Self::Work(work) => work.validate(now, expires),
            Self::Turnstile { action, nonce } => turnstile::Request {
                usage: Use {
                    scope: usage.scope,
                    action: usage.action,
                    maximum: usage.maximum,
                },
                widget_action: action,
                nonce,
                expires,
            }
            .validate(now),
        }
    }
}
/// Dummy provider result plus a labelled price basis. No credentials or transport.
pub struct Offer {
    /// Requirements to validate through the real domain path.
    pub requirement: Requirement,
    /// Explicit fixture outcome; it never authenticates effort.
    pub outcome: Outcome,
    /// Explicit price bound, including failed-attempt fees.
    pub price: Price,
    /// Fixture provenance.
    pub source: String,
    /// Exclusive price validity.
    pub valid_until: u64,
}
/// Caller policy for the complete simulated action.
pub struct Settings<'a> {
    /// Accepted capability required in every chosen option.
    pub required: &'a str,
    /// Requested provider order or maximum-cost ordering.
    pub order: CostOrder,
    /// Total exposure budget.
    pub budget: Amount,
    /// Maximum attempts.
    pub max_attempts: usize,
    /// Trusted fixture time.
    pub now: u64,
    /// Action deadline, shared with real request validation.
    pub expires: u64,
}
/// Simulation cannot be converted into an authenticated `Proof`.
#[derive(Debug)]
pub struct Simulation {
    /// Explicit terminal dummy outcome.
    pub outcome: Outcome,
    /// Selected mechanism, if an attempt ran.
    pub mechanism: Option<&'static str>,
    /// Conservatively reserved fees from the real planner.
    pub exposure: Amount,
    /// Attempts admitted by the real planner.
    pub attempts: usize,
    /// Planner stop after safe failures; all incurred exposure remains visible.
    pub stop: Option<cfbk::cost::Error>,
}
/// Validate real requirements and exercise cfbk planning/fallback using dummy outcomes.
/// No challenge is signed, credential accepted, provider contacted or usage state mutated.
pub fn simulate(
    usage: &Use<'_>,
    offers: Vec<Offer>,
    settings: Settings<'_>,
) -> Result<Simulation, Error> {
    for offer in &offers {
        offer
            .requirement
            .validate(usage, settings.now, settings.expires)?;
    }
    let priced = offers
        .iter()
        .enumerate()
        .map(|(id, offer)| CostOffer {
            candidate: Candidate::new(id, [offer.requirement.capability()]),
            quote: Quote {
                price: offer.price.clone(),
                source: offer.source.clone(),
                valid_until: offer.valid_until.min(settings.expires),
                binding: format!("simulation:{id}"),
            },
        })
        .collect();
    let plan = Plan::new(
        priced,
        Config::new(0..offers.len(), [settings.required]),
        settings.order,
        settings.budget,
        settings.max_attempts,
        Mode::Simulation,
        settings.now,
    )
    .map_err(|_| Error::Cost)?;
    let mut cascade = plan.start();
    loop {
        let permit = match cascade.begin(settings.now) {
            Ok(permit) => permit,
            Err(error) => {
                return Ok(Simulation {
                    outcome: Outcome::SafeFailure,
                    mechanism: None,
                    exposure: cascade.exposure(),
                    attempts: cascade.attempts(),
                    stop: Some(error),
                });
            }
        };
        let offer = &offers[*permit.candidate()];
        cascade
            .complete(offer.outcome, None)
            .expect("an admitted pending attempt with no actual charge always reconciles");
        if offer.outcome != Outcome::SafeFailure {
            return Ok(Simulation {
                outcome: offer.outcome,
                mechanism: Some(offer.requirement.capability()),
                exposure: cascade.exposure(),
                attempts: cascade.attempts(),
                stop: None,
            });
        }
    }
}
