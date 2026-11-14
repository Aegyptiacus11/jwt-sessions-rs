//! Access tokens: short-lived, stateless HS256 JWTs.
//!
//! Stateless on purpose: checking one costs an HMAC, not a database read, which is why they
//! are short-lived (15 minutes by default). Revoking a session takes effect at the next
//! refresh, and an access token outlives its session by at most its own lifetime. Refresh
//! tokens are the stateful half (`refresh.rs`).

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{Map, Value};

use crate::random;

const ALGORITHM: Algorithm = Algorithm::HS256;
/// Set by the library; an application's extra claims may not replace them.
const RESERVED_CLAIMS: [&str; 8] = ["sub", "typ", "iat", "exp", "nbf", "jti", "iss", "aud"];

/// The verified claims of an access token.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims(pub Map<String, Value>);

impl Claims {
    /// The subject: the user's id.
    pub fn sub(&self) -> &str {
        // `verify` refuses a token without a string `sub`.
        self.0
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    pub fn get(&self, claim: &str) -> Option<&Value> {
        self.0.get(claim)
    }
}

/// Malformed, forged, expired, or not an access token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid access token: {0}")]
pub struct InvalidToken(pub String);

/// Settings an [`AccessTokens`] refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("the signing secret must be at least 32 bytes")]
    ShortSecret,
    #[error("the time to live must be at least one second")]
    ZeroTtl,
    #[error("{0}")]
    Other(String),
}

/// Why a token was not issued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssueError {
    #[error("claims may not set {0:?}")]
    ReservedClaims(Vec<String>),
    #[error("signing failed: {0}")]
    Signing(String),
}

/// Issues and verifies access tokens with one secret.
#[derive(Clone)]
pub struct AccessTokens {
    encoding: EncodingKey,
    decoding: DecodingKey,
    ttl: Duration,
    issuer: Option<String>,
    audience: Option<String>,
    leeway: Duration,
}

impl fmt::Debug for AccessTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the secret.
        f.debug_struct("AccessTokens")
            .field("ttl", &self.ttl)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("leeway", &self.leeway)
            .finish_non_exhaustive()
    }
}

impl AccessTokens {
    /// Tokens signed with `secret`, at least 32 bytes (RFC 7518 3.2: an HS256 key must be at
    /// least as long as the hash), valid for 15 minutes.
    pub fn new(secret: &str) -> Result<Self, ConfigError> {
        if secret.len() < 32 {
            return Err(ConfigError::ShortSecret);
        }
        let other = |e: jsonwebtoken::errors::Error| ConfigError::Other(e.to_string());
        Ok(Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()).map_err(other)?,
            decoding: DecodingKey::from_secret(secret.as_bytes()).map_err(other)?,
            ttl: Duration::from_secs(15 * 60),
            issuer: None,
            audience: None,
            leeway: Duration::ZERO,
        })
    }

    /// How long a token is valid; whole seconds, at least one.
    pub fn with_ttl(mut self, ttl: Duration) -> Result<Self, ConfigError> {
        if ttl.as_secs() == 0 {
            return Err(ConfigError::ZeroTtl);
        }
        self.ttl = ttl;
        Ok(self)
    }

    /// Set `iss`, and require it on verification.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set `aud`, and require it on verification.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Clock skew tolerated when checking `exp` and `nbf`.
    pub fn with_leeway(mut self, leeway: Duration) -> Self {
        self.leeway = leeway;
        self
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// A token for `subject` carrying the application's extra `claims`.
    pub fn issue(&self, subject: &str, claims: &Map<String, Value>) -> Result<String, IssueError> {
        self.issue_at(subject, claims, SystemTime::now())
    }

    /// [`issue`](Self::issue) as if it were `now`.
    pub fn issue_at(
        &self,
        subject: &str,
        claims: &Map<String, Value>,
        now: SystemTime,
    ) -> Result<String, IssueError> {
        let mut clash: Vec<String> = RESERVED_CLAIMS
            .iter()
            .filter(|c| claims.contains_key(**c))
            .map(|c| (*c).to_owned())
            .collect();
        if !clash.is_empty() {
            clash.sort();
            return Err(IssueError::ReservedClaims(clash));
        }
        let iat = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut payload = claims.clone();
        payload.insert("sub".into(), subject.into());
        payload.insert("typ".into(), "access".into());
        payload.insert("iat".into(), iat.into());
        payload.insert("exp".into(), (iat + self.ttl.as_secs()).into());
        payload.insert("jti".into(), random::id().into());
        if let Some(issuer) = &self.issuer {
            payload.insert("iss".into(), issuer.as_str().into());
        }
        if let Some(audience) = &self.audience {
            payload.insert("aud".into(), audience.as_str().into());
        }
        jsonwebtoken::encode(&Header::new(ALGORITHM), &payload, &self.encoding)
            .map_err(|e| IssueError::Signing(e.to_string()))
    }

    /// The token's claims, or [`InvalidToken`].
    pub fn verify(&self, token: &str) -> Result<Claims, InvalidToken> {
        // Pinned: the algorithm is never taken from the token.
        let mut validation = Validation::new(ALGORITHM);
        validation.leeway = self.leeway.as_secs();
        validation.validate_nbf = true;
        let mut required = vec!["exp", "sub"];
        if let Some(issuer) = &self.issuer {
            validation.set_issuer(&[issuer]);
            required.push("iss");
        }
        if let Some(audience) = &self.audience {
            validation.set_audience(&[audience]);
            required.push("aud");
        }
        validation.set_required_spec_claims(&required);

        let claims = jsonwebtoken::decode::<Map<String, Value>>(token, &self.decoding, &validation)
            .map_err(|e| InvalidToken(e.to_string()))?
            .claims;
        if !claims.get("sub").is_some_and(Value::is_string) {
            return Err(InvalidToken("sub is not a string".into()));
        }
        if !claims.get("iat").is_some_and(Value::is_number) {
            return Err(InvalidToken("no iat".into()));
        }
        if claims.get("typ").and_then(Value::as_str) != Some("access") {
            return Err(InvalidToken("not an access token".into()));
        }
        Ok(Claims(claims))
    }
}
