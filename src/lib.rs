//! First-party authentication: login and password sign-in, short-lived access tokens, and
//! refresh tokens that rotate on every use and give themselves away when stolen.
//!
//! It is for applications that own their users and do not want an identity provider.
//! Authorization, who may do what, is deliberately not here; it belongs to the application.
//!
//! - [`AccessTokens`]: stateless HS256 JWTs, 15 minutes by default.
//! - [`RefreshTokens`]: opaque random tokens in families, over a [`RefreshStore`]
//!   ([`MemoryRefreshStore`], or `SqlRefreshStore` with the `sqlx` feature).
//! - [`Auth`]: sign in, renew, sign out, over the application's [`UserStore`].
//! - `http` (the `axum` feature): the four endpoints and the `Claims` extractor.
//!
//! The README has the HTTP contract and what a browser client has to do.

mod core;
mod memory;
mod passwords;
mod random;
mod refresh;
mod tokens;

#[cfg(feature = "axum")]
pub mod http;
#[cfg(feature = "sqlx")]
mod sql;

pub use crate::core::{Auth, AuthError, AuthUser, Session, UserStore};
pub use crate::memory::MemoryRefreshStore;
pub use crate::passwords::{MalformedHash, check_password, hash_password, needs_rehash};
pub use crate::refresh::{
    Reason, RefreshError, RefreshRecord, RefreshStore, RefreshTokens, Rotated, StoreError,
    token_hash,
};
#[cfg(feature = "sqlx")]
pub use crate::sql::SqlRefreshStore;
pub use crate::tokens::{AccessTokens, Claims, ConfigError, InvalidToken, IssueError};
