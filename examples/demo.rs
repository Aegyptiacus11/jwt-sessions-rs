//! A complete application: `cargo run --example demo --features axum`, then
//!
//! ```sh
//! curl -i -c jar -H 'content-type: application/json' \
//!   -d '{"email":"ada@example.com","password":"correct horse"}' 127.0.0.1:4000/api/v1/auth/login
//! curl -H "Authorization: Bearer <access_token>" 127.0.0.1:4000/api/v1/whoami
//! curl -i -b jar -c jar -X POST 127.0.0.1:4000/api/v1/auth/refresh
//! ```

use std::sync::Arc;

use axum::routing::get;
use axum::{Json, Router};
use jwt_sessions::http::{CookieSettings, auth_router};
use jwt_sessions::{
    AccessTokens, Auth, AuthUser, Claims, MemoryRefreshStore, RefreshTokens, StoreError, UserStore,
    hash_password,
};
use serde_json::{Value, json};

/// One user, in memory. An application reads its own users table here.
struct Users(AuthUser);

impl UserStore for Users {
    async fn by_login(&self, login: &str) -> Result<Option<AuthUser>, StoreError> {
        Ok((login.eq_ignore_ascii_case("ada@example.com")).then(|| self.0.clone()))
    }

    async fn by_id(&self, user_id: &str) -> Result<Option<AuthUser>, StoreError> {
        Ok((user_id == self.0.id).then(|| self.0.clone()))
    }
}

async fn whoami(claims: Claims) -> Json<Value> {
    Json(json!({"sub": claims.sub(), "role": claims.get("role")}))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ada = AuthUser {
        id: "u1".into(),
        password_hash: hash_password("correct horse"),
        active: true,
        claims: json!({"role": "admin"})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    };
    // A real application reads its secret from its settings, never from the source.
    let access = AccessTokens::new("demo-secret-change-me-at-least-32-bytes")?;
    let refresh = RefreshTokens::new(MemoryRefreshStore::new());
    let auth = Arc::new(Auth::new(Users(ada), access.clone(), refresh));

    // Plain HTTP on localhost, so the cookie cannot be Secure here.
    let cookie = CookieSettings {
        secure: false,
        ..CookieSettings::default()
    };
    let app = Router::new()
        .nest("/api/v1", auth_router(auth, cookie)?)
        .route("/api/v1/whoami", get(whoami))
        .with_state(access);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000").await?;
    println!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
