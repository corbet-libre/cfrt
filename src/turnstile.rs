//! Cloudflare Turnstile Siteverify integration using maintained HTTP/form/JSON libraries.
//! The host supplies TLS transport, disables redirects/retries and bounds response bodies.
use crate::{Consumption, Disclosure, DispatchState, Error, Proof, ProviderReport, Use, digest};
use cfbk::cost::{DispatchPermit, Mode, Price, Quote};
use zeroize::Zeroizing;

/// Trusted transport. Network failures are ambiguous, never automatically retried.
pub trait Transport {
    /// POST the exact request once, over authenticated TLS, to its fixed origin.
    /// The library has already required atomic host dispatch/budget reservation.
    /// Recheck a fresh trusted clock against quote.valid_until immediately before
    /// I/O, including after transport queueing.
    /// No redirects, hidden SDK retries, logging bodies or disk caches. Bound the
    /// response while reading it (64 KiB maximum), including decompression.
    fn send(
        &self,
        request: http::Request<Vec<u8>>,
        quote: &Quote,
    ) -> impl std::future::Future<Output = Result<http::Response<Vec<u8>>, Error>>;
}

/// Provider configuration supplied by the operator, not member-controlled.
pub struct Config {
    /// Stable adapter/account instance, independent of rotating credentials.
    pub instance: String,
    /// Configured widget hostname, compared exactly to the provider result.
    pub hostname: String,
    /// Cloudflare server secret; never returned to members.
    pub secret: String,
    /// Production or explicit provider sandbox; local simulation is separate.
    pub mode: Mode,
}

/// Authoritative action requirements. The member receives only the widget fields.
pub struct Request<'a> {
    /// Caller-defined usage scope, action identity and limit.
    pub usage: Use<'a>,
    /// Expected widget action, 1–32 ASCII alphanumeric, underscore or hyphen.
    pub widget_action: &'a str,
    /// Fresh host-generated opaque nonce, 1–255 characters; never a member identifier.
    pub nonce: &'a str,
    /// Host deadline, at most five minutes ahead when preparing dispatch.
    pub expires: u64,
}

impl Request<'_> {
    /// Pass this exact value as widget `cData`; it binds the response to the action.
    pub fn challenge_data(&self) -> String {
        digest(&[
            "cfrt.turnstile.context.v1",
            self.usage.scope,
            self.usage.action,
            &self.usage.maximum.to_string(),
            self.widget_action,
            self.nonce,
            &self.expires.to_string(),
        ])
    }
    pub(crate) fn validate(&self, now: u64) -> Result<(), Error> {
        self.usage.validate()?;
        if self.widget_action.is_empty()
            || self.widget_action.len() > 32
            || !self
                .widget_action
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || self.nonce.is_empty()
            || self.nonce.len() > 255
            || self.expires <= now
            || self.expires.saturating_sub(now) > 300
        {
            return Err(Error::Configuration);
        }
        Ok(())
    }
}

/// RAM-only adapter; rich JSON and credentials have no Debug implementation.
pub struct Turnstile<T> {
    instance: String,
    hostname: String,
    secret: Zeroizing<String>,
    mode: Mode,
    transport: T,
}

/// Provider sandbox result cannot be used as production effort evidence.
pub enum Verified {
    /// Authenticated production proof and optional full provider JSON.
    Production {
        /// Minimal requested proof.
        proof: Proof,
        /// Complete available provider response, including unknown extensions.
        upstream: Option<serde_json::Value>,
        /// Exact bounded HTTP reply (status, headers and body bytes) when requested.
        transport: Option<ProviderReport>,
    },
    /// Provider test-key response, never a production proof.
    Sandbox {
        /// Complete response only when explicitly requested.
        upstream: Option<serde_json::Value>,
        /// Exact bounded HTTP reply (status, headers and body bytes) when requested.
        transport: Option<ProviderReport>,
    },
}

impl<T: Transport> Turnstile<T> {
    /// Build a configured adapter; simulation never builds or invokes a transport.
    pub fn new(config: Config, transport: T) -> Result<Self, Error> {
        // Cloudflare publishes these fixed test secrets. Production must reject them.
        let test_key = [
            "1x0000000000000000000000000000000AA",
            "2x0000000000000000000000000000000AA",
            "3x0000000000000000000000000000000AA",
        ]
        .contains(&config.secret.as_str());
        if config.instance.is_empty()
            || config.hostname.is_empty()
            || config.secret.is_empty()
            || config.mode == Mode::Simulation
            || (config.mode == Mode::Production && test_key)
            || (config.mode == Mode::Sandbox && !test_key)
        {
            return Err(Error::Configuration);
        }
        Ok(Self {
            instance: config.instance,
            hostname: config.hostname,
            secret: Zeroizing::new(config.secret),
            mode: config.mode,
            transport,
        })
    }

    fn binding(&self, request: &Request<'_>, token: &str) -> String {
        digest(&[
            "cfrt.turnstile.dispatch.v1",
            &self.instance,
            &self.hostname,
            &format!("{:?}", self.mode),
            &request.challenge_data(),
            token,
        ])
    }

    /// Pure cost preview from an explicit sourced tariff, never a provider request.
    /// Include all service/account fees. Free tiers require a valid explicit zero tariff.
    pub fn preview(
        &self,
        request: &Request<'_>,
        token: &str,
        price: Price,
        source: String,
        valid_until: u64,
        now: u64,
    ) -> Result<Quote, Error> {
        request.validate(now)?;
        if token.is_empty() || token.len() > 2048 {
            return Err(Error::Configuration);
        }
        Ok(Quote {
            price,
            source,
            valid_until: valid_until.min(request.expires),
            binding: self.binding(request, token),
        })
    }

    /// Consume a cost permit, verify provider output and reserve authenticated usage.
    /// Do not call automatically after an uncertain/pending attempt in a cascade.
    pub async fn verify(
        &self,
        request: &Request<'_>,
        token: &str,
        permit: DispatchPermit<String>,
        store: &mut (impl Consumption + DispatchState),
        disclosure: Disclosure,
        now: u64,
    ) -> Result<Verified, Error> {
        request.validate(now)?;
        if token.is_empty() || token.len() > 2048 {
            return Err(Error::Configuration);
        }
        permit
            .validate(&self.binding(request, token), self.mode, now)
            .map_err(|_| Error::Cost)?;
        if permit.candidate() != &self.instance {
            return Err(Error::Cost);
        }
        if !store.reserve_dispatch(permit.quote()) {
            return Err(Error::Cost);
        }
        let body =
            serde_urlencoded::to_string([("secret", self.secret.as_str()), ("response", token)])
                .expect("string pairs encode")
                .into_bytes();
        let wire = http::Request::post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body)
            .expect("fixed URL and header");
        let response = self
            .transport
            .send(wire, permit.quote())
            .await
            .map_err(|_| Error::Uncertain)?;
        if response.body().len() > 65536 {
            return Err(Error::Uncertain);
        }
        let information = serde_json::json!({
            "status": response.status().as_u16(),
            "headers": response.headers().iter().map(|(k,v)| (k.as_str(),v.as_bytes())).collect::<Vec<_>>(),
            "body": response.body(),
        });
        if !response.status().is_success() {
            return Err(Error::Uncertain.with_report(disclosure, information));
        }
        let value: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|_| Error::Uncertain.with_report(disclosure, information.clone()))?;
        if value["success"].as_bool() != Some(true)
            || value["hostname"].as_str() != Some(&self.hostname)
            || value["action"].as_str() != Some(request.widget_action)
            || value["cdata"].as_str() != Some(&request.challenge_data())
        {
            return Err(Error::Rejected.with_report(disclosure, information));
        }
        let upstream = (disclosure == Disclosure::Complete).then_some(value);
        if self.mode == Mode::Sandbox {
            return Ok(Verified::Sandbox {
                upstream,
                transport: (disclosure == Disclosure::Complete)
                    .then_some(ProviderReport(information)),
            });
        }
        let key = digest(&["cfrt.turnstile.proof.v1", &self.instance, token]);
        if !store.reserve(&key, &request.usage, request.expires) {
            return Err(Error::Consumption.with_report(disclosure, information));
        }
        Ok(Verified::Production {
            proof: Proof {
                mechanism: "turnstile",
                expires: request.expires,
            },
            upstream,
            transport: (disclosure == Disclosure::Complete).then_some(ProviderReport(information)),
        })
    }
}
