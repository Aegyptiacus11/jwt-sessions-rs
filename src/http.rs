//! The HTTP contract, for axum.
//!
//! ```text
//! POST /auth/login       {"email", "password"} -> {"access_token", "token_type"}
//!                        + Set-Cookie: the refresh token (httpOnly)
//! POST /auth/refresh     cookie -> {"access_token", "token_type"} + the rotated cookie
//! POST /auth/logout      cookie -> 204; session revoked, cookie cleared
//! POST /auth/logout-all  Bearer -> 204; every session of the user revoked
//! ```
//!
//! The refresh token only ever travels in an httpOnly cookie, never in a body JavaScript can
//! read, and the access token only in response bodies and the `Authorization` header, never
//! in a cookie, so no request is authorised by a cookie alone. The refresh cookie is
//! `SameSite=Lax` by default: a cross-site POST does not carry it, and nothing a cross-site
//! page could make the browser send gets it an access token it could read.
//!
//! Errors are `{"detail": "..."}`; a 401 carries `WWW-Authenticate: Bearer`.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRef, FromRequestParts, OriginalUri, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, COOKIE, SET_COOKIE, WWW_AUTHENTICATE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::core::{Auth, AuthError, Session, UserStore};
use crate::refresh::RefreshStore;
use crate::tokens::{AccessTokens, Claims, ConfigError};

/// The `SameSite` attribute of the refresh cookie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    #[default]
    Lax,
    Strict,
    /// Sent on cross-site requests too; browsers then require `Secure`.
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
            Self::None => "None",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieSettings {
    pub name: String,
    /// `None`: the directory the auth endpoints are served from, worked out per request, so
    /// the cookie goes only to them wherever the router is nested. Set it when the
    /// application sits behind a proxy that rewrites paths.
    pub path: Option<String>,
    /// Off only for local development over plain HTTP.
    pub secure: bool,
    pub same_site: SameSite,
    pub domain: Option<String>,
}

impl Default for CookieSettings {
    fn default() -> Self {
        Self {
            name: "refresh_token".into(),
            path: None,
            secure: true,
            same_site: SameSite::Lax,
            domain: None,
        }
    }
}

/// Characters that can stand in a cookie's Path or Domain without ending the attribute.
fn attribute_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_.~%-".contains(&b))
}

impl CookieSettings {
    fn check(&self) -> Result<(), ConfigError> {
        let name_ok = !self.name.is_empty()
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !name_ok {
            return Err(ConfigError::Other(format!(
                "cookie name {:?}: only letters, digits, - and _",
                self.name
            )));
        }
        for (what, value) in [("path", &self.path), ("domain", &self.domain)] {
            if value.as_deref().is_some_and(|v| !attribute_safe(v)) {
                return Err(ConfigError::Other(format!(
                    "cookie {what} {value:?} is not usable"
                )));
            }
        }
        Ok(())
    }

    fn attributes(&self, path: &str) -> String {
        let mut out = format!(
            "Path={path}; HttpOnly; SameSite={}",
            self.same_site.as_str()
        );
        if self.secure {
            out.push_str("; Secure");
        }
        if let Some(domain) = &self.domain {
            out.push_str("; Domain=");
            out.push_str(domain);
        }
        out
    }

    fn set(&self, token: &str, max_age: u64, path: &str) -> String {
        format!(
            "{}={token}; Max-Age={max_age}; {}",
            self.name,
            self.attributes(path)
        )
    }

    fn clear(&self, path: &str) -> String {
        format!(
            "{}=\"\"; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; {}",
            self.name,
            self.attributes(path)
        )
    }

    /// The value of this cookie in the request, if it has one.
    fn read<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(name, _)| *name == self.name)
            .map(|(_, value)| value.trim_matches('"'))
            .filter(|value| !value.is_empty())
    }
}

/// An error response: `{"detail": ...}`, with the Bearer challenge on a 401.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub status: StatusCode,
    pub detail: String,
    set_cookie: Option<String>,
}

impl Rejection {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            set_cookie: None,
        }
    }

    fn unauthorized(detail: &str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, detail)
    }

    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "Internal error")
    }
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(serde_json::json!({ "detail": self.detail })),
        )
            .into_response();
        let headers = response.headers_mut();
        if self.status == StatusCode::UNAUTHORIZED {
            headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if let Some(cookie) = self.set_cookie {
            match HeaderValue::from_str(&cookie) {
                Ok(value) => {
                    headers.insert(SET_COOKIE, value);
                }
                // The settings and the path were checked, so this is a bug; the answer
                // must not claim the cookie was cleared.
                Err(error) => {
                    tracing::error!(%error, "the refresh cookie is not a header value");
                    return Rejection::internal().into_response();
                }
            }
        }
        response
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let (scheme, token) = headers.get(AUTHORIZATION)?.to_str().ok()?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

/// The verified claims of the request's access token, or 401. Loading the application's own
/// user from `claims.sub()`, and checking it is still allowed in, is the application's
/// business. The state must give an [`AccessTokens`] (`impl FromRef<AppState> for
/// AccessTokens`).
impl<S> FromRequestParts<S> for Claims
where
    AccessTokens: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Some(token) = bearer(&parts.headers) else {
            return Err(Rejection::unauthorized("Not authenticated"));
        };
        AccessTokens::from_ref(state)
            .verify(token)
            .map_err(|_| Rejection::unauthorized("Invalid or expired access token"))
    }
}

struct AuthState<U, S> {
    auth: Arc<Auth<U, S>>,
    cookie: Arc<CookieSettings>,
}

impl<U, S> Clone for AuthState<U, S> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            cookie: self.cookie.clone(),
        }
    }
}

impl<U, S> FromRef<AuthState<U, S>> for AccessTokens {
    fn from_ref(state: &AuthState<U, S>) -> Self {
        state.auth.access.clone()
    }
}

impl<U: UserStore, S: RefreshStore> AuthState<U, S> {
    /// Where the cookie is scoped: the settings' path, or the directory of this request.
    fn cookie_path(&self, uri: &OriginalUri) -> Result<String, Rejection> {
        if let Some(path) = &self.cookie.path {
            return Ok(path.clone());
        }
        let directory = uri
            .path()
            .rsplit_once('/')
            .map_or("", |(directory, _)| directory);
        let directory = if directory.is_empty() { "/" } else { directory };
        // The path comes from the request when the router is nested under a parameter: a `;`
        // in it would add attributes to the cookie.
        if !attribute_safe(directory) {
            return Err(Rejection::new(StatusCode::BAD_REQUEST, "Unusable path"));
        }
        Ok(directory.to_owned())
    }

    fn signed_in(&self, session: Session, path: &str) -> Response {
        let cookie = self.cookie.set(
            &session.refresh_token,
            self.auth.refresh.ttl().as_secs(),
            path,
        );
        let Ok(cookie) = HeaderValue::from_str(&cookie) else {
            tracing::error!("the refresh cookie is not a header value");
            return Rejection::internal().into_response();
        };
        let body = AccessTokenResponse {
            access_token: session.access_token,
            token_type: "bearer",
        };
        let mut response = Json(body).into_response();
        response.headers_mut().insert(SET_COOKIE, cookie);
        // RFC 6749 5.1: a response with a token is not to be stored.
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }

    fn signed_out(&self, path: &str) -> Response {
        match HeaderValue::from_str(&self.cookie.clear(path)) {
            Ok(cookie) => (StatusCode::NO_CONTENT, [(SET_COOKIE, cookie)]).into_response(),
            Err(error) => {
                tracing::error!(%error, "the refresh cookie is not a header value");
                Rejection::internal().into_response()
            }
        }
    }

    fn failed(&self, error: AuthError, path: &str) -> Rejection {
        match error {
            AuthError::InvalidCredentials => Rejection::unauthorized("Invalid email or password"),
            AuthError::RefreshRejected(reason) => {
                tracing::info!(%reason, "refresh token rejected");
                // The cookie is dead either way.
                let mut rejection = Rejection::unauthorized("Session expired - sign in again");
                rejection.set_cookie = Some(self.cookie.clear(path));
                rejection
            }
            error @ (AuthError::Store(_) | AuthError::Internal(_)) => {
                tracing::error!(%error, "authentication failed on our side");
                Rejection::internal()
            }
        }
    }
}

#[derive(Deserialize)]
struct LoginBody {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AccessTokenResponse {
    access_token: String,
    token_type: &'static str,
}

/// The four endpoints under `/auth`, for nesting wherever the application serves its API:
/// `Router::new().nest("/api/v1", auth_router(auth, CookieSettings::default())?)`.
pub fn auth_router<U, S, State2>(
    auth: Arc<Auth<U, S>>,
    cookie: CookieSettings,
) -> Result<Router<State2>, ConfigError>
where
    U: UserStore + 'static,
    S: RefreshStore + 'static,
{
    cookie.check()?;
    let state = AuthState {
        auth,
        cookie: Arc::new(cookie),
    };
    Ok(Router::new()
        .route("/auth/login", post(login::<U, S>))
        .route("/auth/refresh", post(refresh::<U, S>))
        .route("/auth/logout", post(logout::<U, S>))
        .route("/auth/logout-all", post(logout_all::<U, S>))
        .with_state(state))
}

async fn login<U: UserStore, S: RefreshStore>(
    State(state): State<AuthState<U, S>>,
    uri: OriginalUri,
    body: Result<Json<LoginBody>, JsonRejection>,
) -> Result<Response, Rejection> {
    let Json(body) = body.map_err(|e| Rejection::new(e.status(), e.body_text()))?;
    // Bounded: argon2 hashes whatever it is given, and a megabyte password is a cheap way to
    // make a server do expensive work.
    if body.email.is_empty() || body.email.len() > 320 {
        return Err(Rejection::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "email: 1 to 320 bytes",
        ));
    }
    if body.password.is_empty() || body.password.len() > 1024 {
        return Err(Rejection::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "password: 1 to 1024 bytes",
        ));
    }
    let path = state.cookie_path(&uri)?;
    let session = state
        .auth
        .login(&body.email, &body.password)
        .await
        .map_err(|e| state.failed(e, &path))?;
    Ok(state.signed_in(session, &path))
}

async fn refresh<U: UserStore, S: RefreshStore>(
    State(state): State<AuthState<U, S>>,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Result<Response, Rejection> {
    let path = state.cookie_path(&uri)?;
    let Some(token) = state.cookie.read(&headers) else {
        return Err(Rejection::unauthorized("Missing refresh token"));
    };
    let session = state
        .auth
        .renew(token)
        .await
        .map_err(|e| state.failed(e, &path))?;
    Ok(state.signed_in(session, &path))
}

async fn logout<U: UserStore, S: RefreshStore>(
    State(state): State<AuthState<U, S>>,
    uri: OriginalUri,
    headers: HeaderMap,
) -> Result<Response, Rejection> {
    let path = state.cookie_path(&uri)?;
    if let Some(token) = state.cookie.read(&headers) {
        state
            .auth
            .logout(token)
            .await
            .map_err(|e| state.failed(e, &path))?;
    }
    Ok(state.signed_out(&path))
}

async fn logout_all<U: UserStore, S: RefreshStore>(
    State(state): State<AuthState<U, S>>,
    uri: OriginalUri,
    claims: Claims,
) -> Result<Response, Rejection> {
    let path = state.cookie_path(&uri)?;
    state
        .auth
        .logout_everywhere(claims.sub())
        .await
        .map_err(|e| state.failed(e, &path))?;
    Ok(state.signed_out(&path))
}
