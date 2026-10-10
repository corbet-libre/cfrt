//! Official ALTCHA v2 integration. The caller chooses the required work factor.
use crate::{Consumption, Disclosure, Error, Proof, Use, digest};
use altcha::{
    Challenge, CreateChallengeOptions, Solution, VerifySolutionOptions, VerifySolutionResult,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// RAM-only server signer. Diagnostics never expose the signing secret.
pub struct Altcha {
    secret: Zeroizing<String>,
}

/// Caller-selected PBKDF2 search requirements, not a monetary denomination.
#[derive(Clone, Copy)]
pub struct Work {
    /// PBKDF2 iterations per candidate; between 1 and 100,000.
    pub iterations: u32,
    /// Number of zero hexadecimal prefix digits; between 1 and 8.
    pub prefix_digits: usize,
}

impl Work {
    pub(crate) fn validate(&self, now: u64, expires: u64) -> Result<(), Error> {
        if !(1..=100_000).contains(&self.iterations)
            || !(1..=8).contains(&self.prefix_digits)
            || expires <= now
            || expires.saturating_sub(now) > 3600
            || expires > i64::MAX as u64
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// Retain this authoritative envelope in RAM until verification. Only its wire
/// challenge goes to the client; client-returned challenge parameters are not trusted.
pub struct Issued {
    challenge: Challenge,
    scope: String,
    action: String,
    maximum: u64,
    expires: u64,
}

impl Issued {
    /// Signed upstream wire challenge, including all upstream extensions.
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }
}

/// Full upstream result access is explicit and has no Debug implementation.
pub struct Verified {
    /// Minimal production proof after atomic consumption.
    pub proof: Proof,
    /// All upstream verification fields, only when requested.
    pub upstream: Option<VerifySolutionResult>,
}

impl Altcha {
    /// Supply a randomly generated server secret separately from provider credentials.
    pub fn new(secret: String) -> Result<Self, Error> {
        if secret.len() < 32 {
            return Err(Error::Configuration);
        }
        Ok(Self {
            secret: Zeroizing::new(secret),
        })
    }

    /// Create and sign a local challenge bound to a specific opaque action and scope.
    /// Expiry must be within one hour. Upstream also checks the system wall clock.
    pub fn issue(
        &self,
        usage: &Use<'_>,
        work: Work,
        now: u64,
        expires: u64,
    ) -> Result<Issued, Error> {
        usage.validate()?;
        work.validate(now, expires)?;
        let data = BTreeMap::from([(
            "context".into(),
            serde_json::Value::String(digest(&[
                "cfrt.altcha.context.v1",
                usage.scope,
                usage.action,
                &usage.maximum.to_string(),
            ])),
        )]);
        let challenge = altcha::create_challenge(CreateChallengeOptions {
            algorithm: "PBKDF2/SHA-256".into(),
            cost: work.iterations,
            key_prefix: "0".repeat(work.prefix_digits),
            key_length: 32,
            expires_at: Some(expires as i64),
            data: Some(data),
            hmac_signature_secret: Some(self.secret.to_string()),
            ..Default::default()
        })
        .expect("fixed algorithm and validated work produce valid ALTCHA parameters");
        Ok(Issued {
            challenge,
            scope: usage.scope.into(),
            action: usage.action.into(),
            maximum: usage.maximum,
            expires,
        })
    }

    /// Verify with upstream cryptography, then atomically reserve the requested usage.
    /// Client-reported solve time is not trusted or used to infer work value.
    pub fn verify(
        &self,
        issued: &Issued,
        solution: &Solution,
        usage: &Use<'_>,
        store: &mut impl Consumption,
        disclosure: Disclosure,
        now: u64,
    ) -> Result<Verified, Error> {
        usage.validate()?;
        if usage.scope != issued.scope
            || usage.action != issued.action
            || usage.maximum != issued.maximum
            || now >= issued.expires
            || solution.derived_key.len() != 64
        {
            return Err(Error::Rejected);
        }
        let result = altcha::verify_solution(VerifySolutionOptions::new(
            &issued.challenge,
            solution,
            self.secret.as_str(),
        ))
        .expect("privately issued immutable ALTCHA parameters remain valid");
        if !result.verified {
            return Err(Error::Rejected.with_report(disclosure, information(&result)));
        }
        let proof = digest(&[
            "cfrt.altcha.proof.v1",
            usage.scope,
            &issued.challenge.parameters.nonce,
        ]);
        if !store.reserve(&proof, usage, issued.expires) {
            return Err(Error::Consumption.with_report(disclosure, information(&result)));
        }
        Ok(Verified {
            proof: Proof {
                mechanism: "altcha-v2-pbkdf2",
                expires: issued.expires,
            },
            upstream: (disclosure == Disclosure::Complete).then_some(result),
        })
    }
}

fn information(result: &VerifySolutionResult) -> serde_json::Value {
    // Exhaustive upstream destructuring makes new fields a compile-time review.
    let VerifySolutionResult {
        expired,
        invalid_signature,
        invalid_solution,
        time,
        verified,
    } = result;
    serde_json::json!({"expired":expired,"invalid_signature":invalid_signature,"invalid_solution":invalid_solution,"time":time,"verified":verified})
}
