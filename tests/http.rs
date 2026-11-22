//! The HTTP contract, end to end: an axum application nesting the router under a prefix, as
//! an application would, and a client holding the cookie.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE, WWW_AUTHENTICATE};
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use http_body_util::BodyExt;
use jwt_sessions::http::{CookieSettings, SameSite, auth_router};
use jwt_sessions::{
    AccessTokens, Auth, AuthUser, Claims, MemoryRefreshStore, RefreshRecord, RefreshStore,
    RefreshTokens, StoreError, UserStore, hash_password,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: &str = "test-secret-that-is-comfortably-over-32-bytes";

#[derive(Clone, Default)]
struct Users(Arc<Mutex<HashMap<String, AuthUser>>>);

impl UserStore for Users {
    async fn by_login(&self, login: &str) -> Result<Option<AuthUser>, StoreError> {
        Ok(self.0.lock().unwrap().get(&login.to_lowercase()).cloned())
    }

    async fn by_id(&self, user_id: &str) -> Result<Option<AuthUser>, StoreError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .values()
            .find(|u| u.id == user_id)
            .cloned())
    }
}

fn ada() -> Users {
    let users = Users::default();
    users.0.lock().unwrap().insert(
        "ada@example.com".into(),
        AuthUser {
            id: "u1".into(),
            password_hash: hash_password("pw-ada"),
            active: true,
            claims: json!({"role": "admin"}).as_object().unwrap().clone(),
        },
    );
    users
}

async fn whoami(claims: Claims) -> Json<Value> {
    Json(json!({"sub": claims.sub(), "role": claims.get("role")}))
}

fn app_with<U: UserStore + 'static, S: RefreshStore + 'static>(
    users: U,
    store: S,
    cookie: CookieSettings,
) -> Router {
    let access = AccessTokens::new(SECRET).unwrap();
    let refresh = RefreshTokens::new(store).with_reuse_grace(Duration::ZERO);
    let auth = Arc::new(Auth::new(users, access.clone(), refresh));
    Router::new()
        .nest("/api/v1", auth_router(auth, cookie).unwrap())
        .route("/api/v1/whoami", get(whoami))
        .with_state(access)
}

/// Plain HTTP in the tests, so the cookie cannot be Secure here.
fn insecure() -> CookieSettings {
    CookieSettings {
        secure: false,
        ..CookieSettings::default()
    }
}

fn app(users: Users) -> Router {
    app_with(users, MemoryRefreshStore::new(), insecure())
}

struct Reply {
    status: StatusCode,
    set_cookie: Option<String>,
    challenge: Option<String>,
    body: Value,
}

impl Reply {
    /// The refresh token the response's cookie carries.
    fn cookie(&self) -> String {
        let header = self.set_cookie.as_deref().expect("a Set-Cookie header");
        let value = header
            .split(';')
            .next()
            .unwrap()
            .strip_prefix("refresh_token=")
            .unwrap();
        value.to_owned()
    }

    fn access_token(&self) -> String {
        self.body["access_token"]
            .as_str()
            .expect("an access token")
            .to_owned()
    }
}

async fn reply(response: Response) -> Reply {
    let header = |name| {
        response
            .headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    };
    let (status, set_cookie, challenge) = (
        response.status(),
        header(SET_COOKIE),
        header(WWW_AUTHENTICATE),
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    Reply {
        status,
        set_cookie,
        challenge,
        body,
    }
}

async fn post(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    body: Option<Value>,
) -> Reply {
    let mut request = Request::post(path);
    if let Some(cookie) = cookie {
        request = request.header(
            COOKIE,
            format!("theme=dark; refresh_token={cookie}; lang=en"),
        );
    }
    if let Some(bearer) = bearer {
        request = request.header(AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let body = match body {
        Some(json) => {
            request = request.header(CONTENT_TYPE, "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    reply(
        app.clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap(),
    )
    .await
}

async fn login(app: &Router) -> Reply {
    let body = json!({"email": "Ada@example.com", "password": "pw-ada"});
    let reply = post(app, "/api/v1/auth/login", None, None, Some(body)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    reply
}

async fn refresh_as(app: &Router, cookie: &str) -> Reply {
    post(app, "/api/v1/auth/refresh", Some(cookie), None, None).await
}

async fn whoami_as(app: &Router, authorization: Option<&str>) -> Reply {
    let mut request = Request::get("/api/v1/whoami");
    if let Some(value) = authorization {
        request = request.header(AUTHORIZATION, value);
    }
    reply(
        app.clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn login_sets_a_scoped_httponly_cookie_and_returns_only_the_access_token() {
    let app = app(ada());
    let signed_in = login(&app).await;
    let keys: Vec<&String> = signed_in.body.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["access_token", "token_type"]);
    assert_eq!(signed_in.body["token_type"], "bearer");

    let cookie = signed_in.set_cookie.clone().unwrap();
    let attributes: Vec<&str> = cookie.split("; ").skip(1).collect();
    // Only the auth endpoints get it, and no script can read it.
    assert_eq!(
        attributes,
        [
            "Max-Age=2592000",
            "Path=/api/v1/auth",
            "HttpOnly",
            "SameSite=Lax"
        ]
    );
    assert!(
        !signed_in.body.to_string().contains(&signed_in.cookie()),
        "the refresh token is in the body"
    );

    let me = whoami_as(&app, Some(&format!("Bearer {}", signed_in.access_token()))).await;
    assert_eq!(me.body, json!({"sub": "u1", "role": "admin"}));
}

#[tokio::test]
async fn the_default_cookie_is_secure_and_settings_reach_it() {
    let app = app_with(ada(), MemoryRefreshStore::new(), CookieSettings::default());
    assert!(
        login(&app)
            .await
            .set_cookie
            .unwrap()
            .ends_with("; SameSite=Lax; Secure")
    );

    let settings = CookieSettings {
        name: "sid".into(),
        path: Some("/auth".into()),
        secure: true,
        same_site: SameSite::Strict,
        domain: Some("example.com".into()),
    };
    let app = app_with(ada(), MemoryRefreshStore::new(), settings);
    let cookie = login(&app).await.set_cookie.unwrap();
    assert!(cookie.starts_with("sid="), "{cookie}");
    assert!(
        cookie.ends_with("; Path=/auth; HttpOnly; SameSite=Strict; Secure; Domain=example.com"),
        "{cookie}"
    );
}

#[tokio::test]
async fn cookie_settings_that_could_inject_attributes_are_refused() {
    let auth = || {
        let access = AccessTokens::new(SECRET).unwrap();
        Arc::new(Auth::new(
            ada(),
            access,
            RefreshTokens::new(MemoryRefreshStore::new()),
        ))
    };
    let bad = [
        CookieSettings {
            name: "a=b".into(),
            ..CookieSettings::default()
        },
        CookieSettings {
            name: String::new(),
            ..CookieSettings::default()
        },
        CookieSettings {
            path: Some("/x; Domain=evil.example".into()),
            ..CookieSettings::default()
        },
        CookieSettings {
            domain: Some("a.example\r\nSet-Cookie: x=y".into()),
            ..CookieSettings::default()
        },
    ];
    for settings in bad {
        assert!(
            auth_router::<_, _, ()>(auth(), settings.clone()).is_err(),
            "{settings:?} was accepted"
        );
    }
}

#[tokio::test]
async fn unknown_email_and_wrong_password_look_the_same() {
    let app = app(ada());
    let a = post(
        &app,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"email": "nobody@example.com", "password": "x"})),
    )
    .await;
    let b = post(
        &app,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"email": "ada@example.com", "password": "x"})),
    )
    .await;
    assert_eq!(
        (a.status, b.status),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(a.body, b.body);
    assert_eq!(a.body, json!({"detail": "Invalid email or password"}));
    assert_eq!((a.set_cookie, b.set_cookie), (None, None));
    assert_eq!(a.challenge.as_deref(), Some("Bearer"));
}

#[tokio::test]
async fn refresh_rotates_the_cookie_and_a_replay_ends_the_session() {
    let app = app(ada());
    let stolen = login(&app).await.cookie();
    let refreshed = refresh_as(&app, &stolen).await;
    assert_eq!(refreshed.status, StatusCode::OK);
    let current = refreshed.cookie();
    assert_ne!(current, stolen);
    assert!(
        whoami_as(&app, Some(&format!("Bearer {}", refreshed.access_token())))
            .await
            .status
            .is_success()
    );

    // Someone presents the old cookie: rejected, and the session is gone, the real user's
    // current cookie with it.
    let replay = refresh_as(&app, &stolen).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    let cleared = replay.set_cookie.unwrap();
    assert!(
        cleared.starts_with("refresh_token=\"\"; Max-Age=0; "),
        "{cleared}"
    );
    assert!(cleared.contains("Path=/api/v1/auth"), "{cleared}");
    assert_eq!(
        refresh_as(&app, &current).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn refresh_without_a_cookie_or_with_an_unknown_one_is_401() {
    let app = app(ada());
    let none = post(&app, "/api/v1/auth/refresh", None, None, None).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(none.body, json!({"detail": "Missing refresh token"}));
    let unknown = refresh_as(&app, "never-issued").await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert!(unknown.set_cookie.unwrap().contains("Max-Age=0"));
    // The access token is not a refresh token.
    let access = login(&app).await.access_token();
    assert_eq!(
        refresh_as(&app, &access).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_revokes_the_session_not_just_the_cookie() {
    let app = app(ada());
    let kept = login(&app).await.cookie();
    let out = post(&app, "/api/v1/auth/logout", Some(&kept), None, None).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(out.set_cookie.unwrap().contains("Max-Age=0"));
    // A copy of the cookie taken before signing out is worthless after.
    assert_eq!(
        refresh_as(&app, &kept).await.status,
        StatusCode::UNAUTHORIZED
    );
    // Signing out again, or with no cookie at all, is not an error.
    assert_eq!(
        post(&app, "/api/v1/auth/logout", Some(&kept), None, None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        post(&app, "/api/v1/auth/logout", None, None, None)
            .await
            .status,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn logout_all_ends_every_session_and_needs_the_access_token() {
    let app = app(ada());
    let first = login(&app).await;
    let second = login(&app).await; // a second device

    // A cookie alone authorises nothing here.
    let by_cookie = post(
        &app,
        "/api/v1/auth/logout-all",
        Some(&first.cookie()),
        None,
        None,
    )
    .await;
    assert_eq!(by_cookie.status, StatusCode::UNAUTHORIZED);

    let out = post(
        &app,
        "/api/v1/auth/logout-all",
        None,
        Some(&first.access_token()),
        None,
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    for cookie in [first.cookie(), second.cookie()] {
        assert_eq!(
            refresh_as(&app, &cookie).await.status,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn a_deactivated_account_cannot_refresh_or_sign_in() {
    let users = ada();
    let app = app(users.clone());
    let cookie = login(&app).await.cookie();
    users
        .0
        .lock()
        .unwrap()
        .get_mut("ada@example.com")
        .unwrap()
        .active = false;
    assert_eq!(
        refresh_as(&app, &cookie).await.status,
        StatusCode::UNAUTHORIZED
    );
    let again = post(
        &app,
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"email": "ada@example.com", "password": "pw-ada"})),
    )
    .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);
    assert_eq!(again.body, json!({"detail": "Invalid email or password"}));
}

#[tokio::test]
async fn a_changed_role_reaches_the_token_at_the_next_refresh() {
    let users = ada();
    let app = app(users.clone());
    let cookie = login(&app).await.cookie();
    users
        .0
        .lock()
        .unwrap()
        .get_mut("ada@example.com")
        .unwrap()
        .claims = json!({"role": "reader"}).as_object().unwrap().clone();
    let access = refresh_as(&app, &cookie).await.access_token();
    assert_eq!(
        whoami_as(&app, Some(&format!("Bearer {access}")))
            .await
            .body["role"],
        "reader"
    );
}

#[tokio::test]
async fn no_or_bad_bearer_is_401_with_a_challenge() {
    let app = app(ada());
    for authorization in [
        None,
        Some("Bearer nonsense"),
        Some("Bearer "),
        Some("Basic dTpw"),
        Some("nonsense"),
    ] {
        let reply = whoami_as(&app, authorization).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{authorization:?}");
        assert_eq!(
            reply.challenge.as_deref(),
            Some("Bearer"),
            "{authorization:?}"
        );
    }
    let access = login(&app).await.access_token();
    assert!(
        whoami_as(&app, Some(&format!("bearer {access}")))
            .await
            .status
            .is_success(),
        "the scheme's case"
    );
}

#[tokio::test]
async fn bodies_that_are_not_a_login_are_refused_before_hashing() {
    let app = app(ada());
    let unprocessable = [
        json!({"email": "ada@example.com", "password": "x".repeat(5000)}),
        json!({"email": "ada@example.com", "password": ""}),
        json!({"email": "", "password": "pw-ada"}),
        json!({"email": "a".repeat(321), "password": "pw-ada"}),
        json!({"email": "ada@example.com"}),
        json!({"email": 7, "password": "pw-ada"}),
    ];
    for body in unprocessable {
        let reply = post(&app, "/api/v1/auth/login", None, None, Some(body.clone())).await;
        assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert!(reply.body["detail"].is_string(), "{body}");
        assert_eq!(reply.set_cookie, None);
    }
    let not_json = Request::post("/api/v1/auth/login")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(not_json).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let no_type = Request::post("/api/v1/auth/login")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(no_type).await.unwrap().status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

/// A store whose database is down.
struct Broken;

fn down<T>() -> Result<T, StoreError> {
    Err(StoreError::new("connection refused"))
}

impl RefreshStore for Broken {
    async fn create_family(
        &self,
        _: &str,
        _: &str,
        _: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        down()
    }
    async fn add_token(
        &self,
        _: &str,
        _: &str,
        _: std::time::SystemTime,
        _: std::time::SystemTime,
    ) -> Result<(), StoreError> {
        down()
    }
    async fn get(&self, _: &str) -> Result<Option<RefreshRecord>, StoreError> {
        down()
    }
    async fn mark_used(&self, _: &str, _: std::time::SystemTime) -> Result<bool, StoreError> {
        down()
    }
    async fn revoke_family(&self, _: &str, _: std::time::SystemTime) -> Result<(), StoreError> {
        down()
    }
    async fn revoke_user(&self, _: &str, _: std::time::SystemTime) -> Result<u64, StoreError> {
        down()
    }
    async fn purge(&self, _: std::time::SystemTime) -> Result<u64, StoreError> {
        down()
    }
}

impl UserStore for Broken {
    async fn by_login(&self, _: &str) -> Result<Option<AuthUser>, StoreError> {
        down()
    }
    async fn by_id(&self, _: &str) -> Result<Option<AuthUser>, StoreError> {
        down()
    }
}

/// A store that is down is our failure, never "wrong password" or "signed out": the client
/// keeps its cookie and is told nothing about why.
#[tokio::test]
async fn a_failing_store_is_500_and_leaves_the_cookie_alone() {
    let credentials = Some(json!({"email": "ada@example.com", "password": "pw-ada"}));

    let no_refresh = app_with(ada(), Broken, insecure());
    let login = post(
        &no_refresh,
        "/api/v1/auth/login",
        None,
        None,
        credentials.clone(),
    )
    .await;
    assert_eq!(login.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(login.body, json!({"detail": "Internal error"}));
    assert_eq!(login.set_cookie, None);
    for path in ["/api/v1/auth/refresh", "/api/v1/auth/logout"] {
        let reply = post(&no_refresh, path, Some("some-token"), None, None).await;
        assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR, "{path}");
        assert_eq!(reply.set_cookie, None, "{path}");
        assert_eq!(reply.challenge, None, "{path}");
    }

    let no_users = app_with(Broken, MemoryRefreshStore::new(), insecure());
    let login = post(&no_users, "/api/v1/auth/login", None, None, credentials).await;
    assert_eq!(login.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_malformed_stored_hash_or_reserved_claims_are_500_not_401() {
    let users = ada();
    users
        .0
        .lock()
        .unwrap()
        .get_mut("ada@example.com")
        .unwrap()
        .password_hash = "not-a-hash".into();
    let reply = post(
        &app(users),
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"email": "ada@example.com", "password": "pw-ada"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);

    let users = ada();
    users
        .0
        .lock()
        .unwrap()
        .get_mut("ada@example.com")
        .unwrap()
        .claims = json!({"sub": "someone-else"}).as_object().unwrap().clone();
    let reply = post(
        &app(users),
        "/api/v1/auth/login",
        None,
        None,
        Some(json!({"email": "ada@example.com", "password": "pw-ada"})),
    )
    .await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.set_cookie, None);
}

/// Nested under a path parameter, the cookie's path comes from the request.
#[tokio::test]
async fn a_request_path_that_could_inject_cookie_attributes_is_refused() {
    let access = AccessTokens::new(SECRET).unwrap();
    let auth = Arc::new(Auth::new(
        ada(),
        access,
        RefreshTokens::new(MemoryRefreshStore::new()),
    ));
    let app: Router = Router::new().nest("/{tenant}", auth_router(auth, insecure()).unwrap());
    let body = Some(json!({"email": "ada@example.com", "password": "pw-ada"}));

    let fine = post(&app, "/acme/auth/login", None, None, body.clone()).await;
    assert!(fine.set_cookie.unwrap().contains("Path=/acme/auth;"));
    let injected = post(
        &app,
        "/acme;Domain=evil.example/auth/login",
        None,
        None,
        body,
    )
    .await;
    assert_eq!(injected.status, StatusCode::BAD_REQUEST);
    assert_eq!(injected.set_cookie, None);
}

/// A session another party authenticated: started without a password, and the cookie it
/// hands out is renewed by `/auth/refresh` like one from `/auth/login`.
#[tokio::test]
async fn a_session_started_without_a_password_refreshes_like_any_other() {
    let access = AccessTokens::new(SECRET).unwrap();
    let auth = Arc::new(Auth::new(
        ada(),
        access.clone(),
        RefreshTokens::new(MemoryRefreshStore::new()),
    ));
    let session = auth.start("u1").await.unwrap();
    assert_eq!(session.user_id, "u1");
    assert_eq!(access.verify(&session.access_token).unwrap().sub(), "u1");

    let cookie = insecure()
        .set_cookie(&session.refresh_token, 60, "/api/v1/auth")
        .unwrap();
    assert!(cookie.contains("Path=/api/v1/auth; HttpOnly"), "{cookie}");
    let pair = cookie.split(';').next().unwrap().to_owned();

    let app = Router::new()
        .nest("/api/v1", auth_router(auth, insecure()).unwrap())
        .with_state(access);
    let response = app
        .oneshot(
            Request::post("/api/v1/auth/refresh")
                .header(COOKIE, pair)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn no_session_starts_for_an_unknown_or_deactivated_account() {
    let users = ada();
    let auth = Auth::new(
        users.clone(),
        AccessTokens::new(SECRET).unwrap(),
        RefreshTokens::new(MemoryRefreshStore::new()),
    );
    assert!(matches!(
        auth.start("nobody").await,
        Err(jwt_sessions::AuthError::InvalidCredentials)
    ));
    users
        .0
        .lock()
        .unwrap()
        .get_mut("ada@example.com")
        .unwrap()
        .active = false;
    assert!(matches!(
        auth.start("u1").await,
        Err(jwt_sessions::AuthError::InvalidCredentials)
    ));
}

#[test]
fn a_cookie_path_that_could_add_attributes_is_refused() {
    let cookie = insecure();
    assert!(
        cookie
            .set_cookie("token", 60, "/auth; Domain=evil")
            .is_err()
    );
    assert!(cookie.set_cookie("token", 60, "").is_err());
    assert!(cookie.set_cookie("tok;en", 60, "/auth").is_err());
    // the settings' path wins over the one given
    let fixed = CookieSettings {
        path: Some("/pacs/auth".into()),
        ..insecure()
    };
    assert!(
        fixed
            .set_cookie("token", 60, "/auth")
            .unwrap()
            .contains("Path=/pacs/auth;")
    );
}
