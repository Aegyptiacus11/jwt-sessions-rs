//! The session lifecycle: sign in, refresh, sign out, in terms of the two things an
//! application supplies: where its users are ([`UserStore`]) and where refresh tokens are
//! kept ([`RefreshStore`]).
//!
//! Framework-free; `http` puts it behind HTTP.

use std::future::Future;
use std::time::SystemTime;

use serde_json::{Map, Value};

use crate::passwords::check_password;
use crate::refresh::{Reason, RefreshError, RefreshStore, RefreshTokens, StoreError};
use crate::tokens::{AccessTokens, IssueError};

/// What the library needs to know about a user.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthUser {
    pub id: String,
    pub password_hash: String,
    pub active: bool,
    /// Extra claims for the access token: a role, say. Read again on every refresh, so a
    /// changed role reaches the token within one access lifetime.
    pub claims: Map<String, Value>,
}

/// Where the application's users are.
pub trait UserStore: Send + Sync {
    /// The user signing in as `login` (an email, usually). Normalise case here if logins are
    /// case-insensitive.
    fn by_login(
        &self,
        login: &str,
    ) -> impl Future<Output = Result<Option<AuthUser>, StoreError>> + Send;

    fn by_id(
        &self,
        user_id: &str,
    ) -> impl Future<Output = Result<Option<AuthUser>, StoreError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Wrong login or password, or an inactive account: deliberately one error, so the
    /// response does not say which.
    #[error("invalid login or password")]
    InvalidCredentials,
    /// The refresh token cannot be used; the client must sign in again.
    #[error("refresh token rejected: {0}")]
    RefreshRejected(Reason),
    /// A store failed. Nothing was decided about the credentials.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// The access token could not be made: the user's claims set a reserved one, a stored
    /// password hash is malformed, or signing failed.
    #[error("{0}")]
    Internal(String),
}

impl From<RefreshError> for AuthError {
    fn from(error: RefreshError) -> Self {
        match error {
            RefreshError::Rejected(reason) => Self::RefreshRejected(reason),
            RefreshError::Store(e) => Self::Store(e),
        }
    }
}

impl From<IssueError> for AuthError {
    fn from(error: IssueError) -> Self {
        Self::Internal(error.to_string())
    }
}

/// A signed-in session: the access token for the `Authorization` header, and the refresh
/// token for the cookie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
}

#[derive(Debug)]
pub struct Auth<U, S> {
    pub users: U,
    pub access: AccessTokens,
    pub refresh: RefreshTokens<S>,
}

impl<U: UserStore, S: RefreshStore> Auth<U, S> {
    pub fn new(users: U, access: AccessTokens, refresh: RefreshTokens<S>) -> Self {
        Self {
            users,
            access,
            refresh,
        }
    }

    pub async fn login(&self, login: &str, password: &str) -> Result<Session, AuthError> {
        self.login_at(login, password, SystemTime::now()).await
    }

    /// [`login`](Self::login) as if it were `now`.
    pub async fn login_at(
        &self,
        login: &str,
        password: &str,
        now: SystemTime,
    ) -> Result<Session, AuthError> {
        let user = self.users.by_login(login).await?;
        // Always one argon2 verification, account or not (see passwords.rs); off the async
        // threads, since it takes tens of milliseconds of CPU.
        let (password, hash) = (
            password.to_owned(),
            user.as_ref().map(|u| u.password_hash.clone()),
        );
        let matches =
            tokio::task::spawn_blocking(move || check_password(&password, hash.as_deref()))
                .await
                .map_err(|e| {
                    AuthError::Internal(format!("the password check did not finish: {e}"))
                })?
                .map_err(|e| AuthError::Internal(e.to_string()))?;
        let Some(user) = user.filter(|user| matches && user.active) else {
            return Err(AuthError::InvalidCredentials);
        };
        // The access token first: if the user's claims are refused, no family is left behind.
        let access_token = self.access.issue_at(&user.id, &user.claims, now)?;
        let refresh_token = self.refresh.start(&user.id, now).await?;
        Ok(Session {
            access_token,
            refresh_token,
            user_id: user.id,
        })
    }

    /// A new access token and the refresh token's successor. An account deactivated since
    /// sign-in ends the session.
    pub async fn renew(&self, refresh_token: &str) -> Result<Session, AuthError> {
        self.renew_at(refresh_token, SystemTime::now()).await
    }

    /// [`renew`](Self::renew) as if it were `now`.
    pub async fn renew_at(
        &self,
        refresh_token: &str,
        now: SystemTime,
    ) -> Result<Session, AuthError> {
        let rotated = self.refresh.rotate(refresh_token, now).await?;
        let Some(user) = self
            .users
            .by_id(&rotated.user_id)
            .await?
            .filter(|user| user.active)
        else {
            self.refresh.revoke(&rotated.token, now).await?;
            return Err(AuthError::RefreshRejected(Reason::Inactive));
        };
        let access_token = self.access.issue_at(&user.id, &user.claims, now)?;
        Ok(Session {
            access_token,
            refresh_token: rotated.token,
            user_id: user.id,
        })
    }

    /// End the session the refresh token belongs to.
    pub async fn logout(&self, refresh_token: &str) -> Result<(), AuthError> {
        Ok(self
            .refresh
            .revoke(refresh_token, SystemTime::now())
            .await?)
    }

    /// End every session of the user; how many there were. Call it on deactivation and on a
    /// password change.
    pub async fn logout_everywhere(&self, user_id: &str) -> Result<u64, AuthError> {
        Ok(self.refresh.revoke_user(user_id, SystemTime::now()).await?)
    }
}
