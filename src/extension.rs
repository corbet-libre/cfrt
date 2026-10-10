//! Open trusted adapter service for useful computation and other established effort mechanisms.
//! Implementations integrate an independent verifier; member JSON is never an authenticator.
use crate::{Consumption, Disclosure, DispatchState, Error, Proof, Use, digest};
use cfbk::cost::{DispatchPermit, Mode, Price, Quote};

/// Caller-authored mechanism requirements, fixed before accepting evidence.
pub struct Request<'a> {
    /// Scope, action and permitted usage ceiling.
    pub usage: Use<'a>,
    /// Exact mechanism-specific job/work requirements interpreted by the adapter.
    pub requirements: &'a serde_json::Value,
    /// Fresh opaque host challenge binding, never a personal identifier.
    pub nonce: &'a str,
    /// Exclusive application deadline.
    pub expires: u64,
}
impl Request<'_> {
    fn validate(&self, now: u64) -> Result<(), Error> {
        self.usage.validate()?;
        if self.nonce.is_empty()
            || self.expires <= now
            || self.requirements.to_string().len() > 65536
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    /// Opaque binding covering all requested semantics, authenticated by the provider adapter.
    pub fn binding(&self) -> String {
        digest(&[
            "cfrt.extension.context.v1",
            self.usage.scope,
            self.usage.action,
            &self.usage.maximum.to_string(),
            &self.requirements.to_string(),
            self.nonce,
            &self.expires.to_string(),
        ])
    }
}
/// Independently authenticated result, returned only by trusted application adapter code.
/// Public fields permit integrations; there is deliberately no member-input Deserialize API.
pub struct Authenticated {
    /// Globally unique proof/job-result ID in this adapter's actual namespace.
    pub id: String,
    /// Exact request binding verified by the underlying mechanism.
    pub context: String,
    /// Exclusive evidence deadline; it can only shorten caller validity.
    pub expires: u64,
    /// All available upstream fields, released only on explicit request.
    pub upstream: serde_json::Value,
}
/// Trusted provider integration; must verify actual requested work using maintained upstream code.
pub trait Adapter {
    /// Stable mechanism/account instance, independent of rotatable credentials.
    fn instance(&self) -> &str;
    /// Exact established mechanism, not an inferred claim of useful work or personhood.
    fn mechanism(&self) -> &'static str;
    /// Explicit production or sandbox; simulation never invokes this trait.
    fn mode(&self) -> Mode;
    /// Authenticate bounded evidence and every requested job/work requirement.
    /// Host cost reservation already occurred. No implicit retry or unquoted operation.
    fn verify(
        &self,
        evidence: &[u8],
        request: &Request<'_>,
        quote: &Quote,
    ) -> impl std::future::Future<Output = Result<Authenticated, Error>>;
}
/// Open effort service. No credential discovery or concrete useful-computation vendor is assumed.
pub struct Service<A> {
    /// Explicitly configured trusted implementation.
    pub adapter: A,
}
/// Sandbox results remain distinct and cannot carry a production proof.
pub enum Verified {
    /// Authenticated result after atomic production consumption.
    Production {
        /// Minimal authenticated effort fact.
        proof: Proof,
        /// Complete upstream response only when requested.
        upstream: Option<serde_json::Value>,
    },
    /// Explicit provider sandbox response.
    Sandbox {
        /// Complete upstream response only when requested.
        upstream: Option<serde_json::Value>,
    },
}
impl<A: Adapter> Service<A> {
    fn validate(&self, request: &Request<'_>, evidence: &[u8], now: u64) -> Result<(), Error> {
        request.validate(now)?;
        if self.adapter.instance().is_empty()
            || self.adapter.mechanism().is_empty()
            || self.adapter.mode() == Mode::Simulation
            || evidence.len() > 65536
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
    fn binding(&self, request: &Request<'_>, evidence: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        digest(&[
            "cfrt.extension.dispatch.v1",
            self.adapter.instance(),
            self.adapter.mechanism(),
            &format!("{:?}", self.adapter.mode()),
            &request.binding(),
            &hex::encode(Sha256::digest(evidence)),
        ])
    }
    /// Inert request-bound preview from an explicit price basis, never a provider query.
    pub fn preview(
        &self,
        request: &Request<'_>,
        evidence: &[u8],
        price: Price,
        source: String,
        valid_until: u64,
        now: u64,
    ) -> Result<Quote, Error> {
        self.validate(request, evidence, now)?;
        Ok(Quote {
            price,
            source,
            valid_until: valid_until.min(request.expires),
            binding: self.binding(request, evidence),
        })
    }
    /// Require atomic cost admission, authenticate work, and consume only production evidence.
    pub async fn verify(
        &self,
        request: &Request<'_>,
        evidence: &[u8],
        permit: DispatchPermit<String>,
        state: &mut (impl Consumption + DispatchState),
        disclosure: Disclosure,
        now: u64,
    ) -> Result<Verified, Error> {
        self.validate(request, evidence, now)?;
        permit
            .validate(&self.binding(request, evidence), self.adapter.mode(), now)
            .map_err(|_| Error::Cost)?;
        if permit.candidate() != self.adapter.instance() || !state.reserve_dispatch(permit.quote())
        {
            return Err(Error::Cost);
        }
        let result = self
            .adapter
            .verify(evidence, request, permit.quote())
            .await?;
        if result.id.is_empty() || result.context != request.binding() || result.expires <= now {
            return Err(Error::Rejected.with_report(disclosure, result.upstream));
        }
        let expires = result.expires.min(request.expires);
        if self.adapter.mode() == Mode::Sandbox {
            return Ok(Verified::Sandbox {
                upstream: (disclosure == Disclosure::Complete).then_some(result.upstream),
            });
        }
        let key = digest(&[
            "cfrt.extension.proof.v1",
            self.adapter.instance(),
            &result.id,
        ]);
        if !state.reserve(&key, &request.usage, expires) {
            return Err(Error::Consumption.with_report(disclosure, result.upstream));
        }
        Ok(Verified::Production {
            proof: Proof {
                mechanism: self.adapter.mechanism(),
                expires,
            },
            upstream: (disclosure == Disclosure::Complete).then_some(result.upstream),
        })
    }
}
