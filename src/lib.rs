//! Verifiable effort, separated from payment and application policy.
//!
//! ALTCHA and Turnstile perform verification. The caller supplies requirements,
//! atomic consumption and transport. The library never opens storage.
#![forbid(unsafe_code)]

pub mod pow;
pub mod turnstile;

use cfbk::cost::{Amount, Price, Quote, Unit};
use sha2::{Digest, Sha256};

/// Provider errors deliberately carry no challenge, token or credential.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Invalid trusted configuration or caller request.
    #[error("invalid effort configuration")]
    Configuration,
    /// The evidence did not satisfy the requested effort.
    #[error("effort rejected")]
    Rejected,
    /// Atomic consumption declined or is unavailable.
    #[error("effort consumption unavailable")]
    Consumption,
    /// Provider may have consumed the token or charged; do not automatically retry.
    #[error("effort provider outcome uncertain")]
    Uncertain,
    /// Dispatch permit does not authorize this operation.
    #[error("effort cost authorization rejected")]
    Cost,
}

/// Caller-selected action and usage semantics. Use opaque identifiers.
pub struct Use<'a> {
    /// Explicit comparison/consumption scope, including any policy epoch.
    pub scope: &'a str,
    /// Stable identity of this action; retries must reuse it.
    pub action: &'a str,
    /// Maximum distinct actions permitted for one proof in this scope.
    pub maximum: u64,
}

impl Use<'_> {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.scope.is_empty() || self.action.is_empty() || self.maximum == 0 {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Application-owned atomic usage port; implementations may persist opaque keys.
pub trait Consumption {
    /// Atomically reserve one action up to `maximum`, idempotently for that action.
    /// Bind retries to the original maximum and expiry. Never implement as count-then-write.
    fn reserve(&mut self, proof: &str, usage: &Use<'_>, expires: u64) -> bool;
}

/// Authenticated production result, constructible only after verification and consumption.
/// No member effort time or computational value is inferred from this result.
#[derive(Debug)]
pub struct Proof {
    mechanism: &'static str,
    expires: u64,
}

impl Proof {
    /// Mechanism actually verified, not a claim of human uniqueness.
    pub fn mechanism(&self) -> &'static str {
        self.mechanism
    }
    /// Latest usable time, in Unix seconds.
    pub fn expires(&self) -> u64 {
        self.expires
    }
}

/// Explicit output request. Complete results remain private RAM values.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Disclosure {
    /// Return only the requested proof.
    Minimal,
    /// Also return every available upstream verification field.
    Complete,
}

/// A deterministic local test outcome. It is deliberately not a [`Proof`].
#[derive(Debug, PartialEq, Eq)]
pub struct Simulation {
    /// Configured dummy outcome for planning and UI development.
    pub accepted: bool,
}

/// Local simulation does not invoke adapters, consume proofs or access credentials.
pub fn simulate(accepted: bool) -> Simulation {
    Simulation { accepted }
}

/// Exact third-party service fee for a local-only computation (not CPU/hosting cost).
pub fn local_quote(unit: Unit, binding: String, valid_until: u64) -> Quote {
    Quote {
        price: Price::Exact(Amount { unit, atoms: 0 }),
        source: "local computation; no third-party service call".into(),
        binding,
        valid_until,
    }
}

pub(crate) fn digest(fields: &[&str]) -> String {
    // JSON array framing prevents concatenation ambiguity; these are public proof IDs,
    // not hashes of low-entropy phone numbers or other private identities.
    hex::encode(Sha256::digest(
        serde_json::to_vec(fields).expect("strings serialize"),
    ))
}

#[cfg(test)]
mod tests;
