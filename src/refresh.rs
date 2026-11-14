//! Refresh tokens: opaque, rotated on every use, and grouped into families so that a stolen
//! one gives itself away.
//!
//! A login starts a **family**. Every refresh spends the presented token and issues its
//! successor in the same family. A token presented a second time means two parties hold it,
//! the user and whoever copied it, and there is no telling which is which, so the whole
//! family is revoked: both are signed out, and the thief's copy is dead. (A stateless refresh
//! JWT cannot do any of that: a copied one keeps working until it expires, however often the
//! real user refreshes.)
//!
//! One exception, the reuse grace: two tabs of the same browser that refresh at the same
//! moment both send the token the cookie held, and the second arrives already spent. Within
//! the grace window a spent token gets a successor instead of revoking the family. It is a
//! window a thief could use too, if they replay within those seconds of the real refresh;
//! the default is 10 s, and zero turns it off.
//!
//! Tokens are random, not JWTs, and only their SHA-256 is stored, so a leaked table holds
//! nothing that can be presented.

use std::fmt;
use std::future::Future;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

use crate::random;

/// The SHA-256 of a refresh token, in hex: what a store keeps.
pub fn token_hash(token: &str) -> String {
    random::hex(&Sha256::digest(token.as_bytes()))
}

/// One refresh token as stored, with its family's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRecord {
    pub token_hash: String,
    pub family_id: String,
    pub user_id: String,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub used_at: Option<SystemTime>,
    /// When the family was revoked: logout, reuse, or revoke-all.
    pub family_revoked_at: Option<SystemTime>,
}

/// A store (of refresh tokens or of users) failed: the database did not answer, say. Never a
/// verdict on a token or a password.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct StoreError(#[source] pub Box<dyn std::error::Error + Send + Sync>);

impl StoreError {
    pub fn new(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(error.into())
    }
}

/// Where families and tokens live.
///
/// `mark_used` must be atomic: of two concurrent calls for the same token, exactly one
/// returns `true`.
pub trait RefreshStore: Send + Sync {
    fn create_family(
        &self,
        family_id: &str,
        user_id: &str,
        at: SystemTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn add_token(
        &self,
        token_hash: &str,
        family_id: &str,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn get(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = Result<Option<RefreshRecord>, StoreError>> + Send;

    /// Mark the token spent at `at`; `false` when it is unknown or already spent.
    fn mark_used(
        &self,
        token_hash: &str,
        at: SystemTime,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;

    fn revoke_family(
        &self,
        family_id: &str,
        at: SystemTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Revoke every live family of the user; how many there were.
    fn revoke_user(
        &self,
        user_id: &str,
        at: SystemTime,
    ) -> impl Future<Output = Result<u64, StoreError>> + Send;

    /// Drop tokens that expired before `before`; how many.
    fn purge(&self, before: SystemTime) -> impl Future<Output = Result<u64, StoreError>> + Send;
}

/// Why a refresh token cannot be used. For logs; a client is told only that it must sign in
/// again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Never issued, or purged.
    Unknown,
    Expired,
    /// Its family was revoked: a sign-out, a reuse, or revoke-all.
    Revoked,
    /// Already spent: the family has just been revoked.
    Reused,
    /// The account no longer exists or was deactivated.
    Inactive,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Reused => "reused",
            Self::Inactive => "inactive",
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error("refresh token rejected: {0}")]
    Rejected(Reason),
    #[error("refresh store: {0}")]
    Store(#[from] StoreError),
}

/// A spent token's successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    pub token: String,
    pub user_id: String,
    pub family_id: String,
}

/// Starts, rotates and revokes refresh tokens over a store.
#[derive(Debug, Clone)]
pub struct RefreshTokens<S> {
    store: S,
    ttl: Duration,
    reuse_grace: Duration,
}

impl<S: RefreshStore> RefreshTokens<S> {
    /// Tokens valid for 30 days, with a reuse grace of 10 seconds.
    pub fn new(store: S) -> Self {
        Self {
            store,
            ttl: Duration::from_secs(30 * 24 * 3600),
            reuse_grace: Duration::from_secs(10),
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// How long after its first use a spent token still gets a successor; zero turns it off.
    pub fn with_reuse_grace(mut self, grace: Duration) -> Self {
        self.reuse_grace = grace;
        self
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// A new family for a fresh login, and its first token.
    pub async fn start(&self, user_id: &str, now: SystemTime) -> Result<String, StoreError> {
        let family_id = random::id();
        self.store.create_family(&family_id, user_id, now).await?;
        self.issue(&family_id, now).await
    }

    /// Spend `token` and return its successor, or [`RefreshError::Rejected`], having revoked
    /// the family if the token had already been spent.
    pub async fn rotate(&self, token: &str, now: SystemTime) -> Result<Rotated, RefreshError> {
        let hash = token_hash(token);
        let Some(record) = self.store.get(&hash).await? else {
            return Err(RefreshError::Rejected(Reason::Unknown));
        };
        if record.family_revoked_at.is_some() {
            return Err(RefreshError::Rejected(Reason::Revoked));
        }
        if record.expires_at <= now {
            return Err(RefreshError::Rejected(Reason::Expired));
        }
        if !self.store.mark_used(&hash, now).await? {
            let used_at = self.store.get(&hash).await?.and_then(|spent| spent.used_at);
            // A clock that went backwards counts as no time passed.
            let within_grace = !self.reuse_grace.is_zero()
                && used_at.is_some_and(|at| {
                    now.duration_since(at).unwrap_or(Duration::ZERO) <= self.reuse_grace
                });
            if !within_grace {
                self.store.revoke_family(&record.family_id, now).await?;
                return Err(RefreshError::Rejected(Reason::Reused));
            }
        }
        let successor = self.issue(&record.family_id, now).await?;
        Ok(Rotated {
            token: successor,
            user_id: record.user_id,
            family_id: record.family_id,
        })
    }

    /// End the session `token` belongs to (sign-out). Unknown tokens are ignored: signing out
    /// twice is not an error.
    pub async fn revoke(&self, token: &str, now: SystemTime) -> Result<(), StoreError> {
        if let Some(record) = self.store.get(&token_hash(token)).await? {
            self.store.revoke_family(&record.family_id, now).await?;
        }
        Ok(())
    }

    /// End every session of the user: sign out everywhere, a password change, a deactivated
    /// account. How many sessions there were.
    pub async fn revoke_user(&self, user_id: &str, now: SystemTime) -> Result<u64, StoreError> {
        self.store.revoke_user(user_id, now).await
    }

    /// Drop tokens that expired before `before`; how many. Run it now and then: on start-up
    /// is enough for most applications.
    pub async fn purge(&self, before: SystemTime) -> Result<u64, StoreError> {
        self.store.purge(before).await
    }

    async fn issue(&self, family_id: &str, now: SystemTime) -> Result<String, StoreError> {
        let token = random::token();
        self.store
            .add_token(&token_hash(&token), family_id, now, now + self.ttl)
            .await?;
        Ok(token)
    }
}
