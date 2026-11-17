# jwt-sessions

First-party authentication for Rust services: login and password sign-in, short-lived access
tokens, and refresh tokens that rotate on every use and give themselves away when stolen. With
an [axum](https://github.com/tokio-rs/axum) router for the HTTP contract.

It is for applications that own their users and do not want an identity provider.
Authorization, who may do what, is deliberately not here; it belongs to the application.

This is the Rust counterpart of the Python
[jwt-sessions](https://github.com/Aegyptiacus11/jwt-sessions) for FastAPI: the same contract
over HTTP, so a client written for one works with the other.

> Status: 0.1.0, the first release; the API may still change before 1.0.

## Installing

```toml
jwt-sessions = { version = "0.1.0", features = ["axum", "sqlx"] }
```

| Feature | Adds |
|---|---|
| `axum` | `jwt_sessions::http`: the router and the `Claims` extractor |
| `sqlx` | `SqlRefreshStore`: refresh tokens in SQLite or Postgres |

Without features the crate is the framework-free core and an in-memory store.

## Using it

```rust
use std::sync::Arc;
use jwt_sessions::http::{CookieSettings, auth_router};
use jwt_sessions::{AccessTokens, Auth, Claims, RefreshTokens, SqlRefreshStore};

let store = SqlRefreshStore::new(pool, "auth_")?; // an sqlx AnyPool
store.create_tables().await?;                     // or put store.schema() in your migrations

let access = AccessTokens::new(&settings.jwt_secret)?;
let auth = Arc::new(Auth::new(MyUsers::new(), access.clone(), RefreshTokens::new(store)));

let app = Router::new()
    .nest("/api/v1", auth_router(auth, CookieSettings::default())?)
    .route("/api/v1/whoami", get(whoami))
    .with_state(access); // any state that gives an AccessTokens (FromRef)

async fn whoami(claims: Claims) -> String {
    claims.sub().to_owned() // the verified claims, or the request got a 401
}
```

`MyUsers` implements `UserStore`: `by_login` and `by_id`, each returning an `AuthUser` (id,
password hash, active, extra claims such as a role).

[examples/demo.rs](examples/demo.rs) is a complete, runnable one:
`cargo run --example demo --features axum`.

## The contract

| | Request | Response |
|---|---|---|
| `POST /auth/login` | `{"email", "password"}` | `{"access_token", "token_type"}` and the refresh cookie |
| `POST /auth/refresh` | the refresh cookie | a new access token and the rotated cookie |
| `POST /auth/logout` | the refresh cookie | `204`; that session is revoked, the cookie cleared |
| `POST /auth/logout-all` | `Authorization: Bearer` | `204`; every session of the user is revoked |

- **The access token** is a JWT (HS256, 15 minutes by default), sent as
  `Authorization: Bearer`. It is never in a cookie, so no request is authorised by a cookie
  alone.
- **The refresh token** is an opaque random value that only ever travels in an `HttpOnly`,
  `SameSite=Lax` cookie scoped to the auth endpoints. JavaScript never sees it, so a script
  injected into the page cannot take it away.
- **Errors** are `{"detail": "..."}`. A 401 carries `WWW-Authenticate: Bearer`; a store that
  fails is a 500, never a 401, and leaves the cookie alone.

### What a client has to do

A browser client is small. There is no client library, and the contract is all it needs:

- Keep the access token in memory, not in storage.
- Call the auth endpoints with `credentials: "include"`, so the cookie travels.
- On load, `POST /auth/refresh` to restore a session; a 401 means signed out.
- On a 401 from the API, refresh **once** and retry; if the refresh fails, the session is gone.
- Never run two refreshes at once from one page: the server spends a refresh token on use,
  and the second would look like a replay (see below). Share one in-flight refresh between
  everything that needs a token.
- Renewing a minute before the access token's `exp` saves the first request after an idle
  spell a round trip.

## What happens to a stolen refresh token

A sign-in starts a **family** of refresh tokens. Each refresh spends the token presented and
issues its successor. A spent token presented again means two parties hold it, the user and
whoever copied it, so the whole family is revoked: both are signed out, and the copy is dead.

A stateless refresh JWT, the usual alternative, can do none of this: a copied one keeps
working until it expires, however often its owner refreshes, and signing out only deletes the
owner's copy.

Two tabs refreshing at the same instant would look like a replay, so a spent token presented
again within the reuse grace (10 s by default; zero turns it off) gets a successor instead.
That window is open to a thief as well, if they replay within those seconds of the real
refresh.

Only the SHA-256 of a refresh token is stored, so a copy of the table holds nothing that can
be presented.

## Also

- Signing in with an unknown login costs the same argon2 verification as a wrong password, so
  response time does not say which logins have accounts. The verification runs off the async
  threads.
- Passwords over 1 KB are refused before hashing.
- The signing secret must be at least 32 bytes, and the JWT algorithm is pinned on
  verification, never read from the token.
- A deactivated account's session ends at its next refresh; its current access token runs out
  within the access lifetime. `Auth::logout_everywhere` ends every session at once: call it on
  deactivation and on a password change.
- `RefreshTokens::purge` drops expired tokens; run it now and then (on start-up is enough for
  most applications).
- `needs_rehash` says when a stored hash was made with weaker parameters than today's.

## Differences from the Python library

- Times in the SQL store are milliseconds since the Unix epoch in `BIGINT` columns, not
  timestamps, so the two libraries do not share tables.
- The cookie's attribute is written `SameSite=Lax`, capitalised.
- A malformed stored password hash, or user claims that set a reserved one, is a 500.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The refresh tests run against the in-memory store and SQLite, and against Postgres when
`JWT_SESSIONS_TEST_POSTGRES_URL` names a server:

```bash
docker run -d --rm --name jwts-pg -p 127.0.0.1:15433:5432 -e POSTGRES_PASSWORD=test postgres:18.6-alpine
JWT_SESSIONS_TEST_POSTGRES_URL=postgres://postgres:test@127.0.0.1:15433/postgres cargo test --all-features
docker stop jwts-pg
```

## License

MIT or Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
