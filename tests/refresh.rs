//! Rotation, reuse detection and revocation, against every store: they are implementations
//! of one contract, and the SQL one is what an application runs.
//!
//! The Postgres run needs `JWT_SESSIONS_TEST_POSTGRES_URL`, e.g.
//! `postgres://postgres:test@127.0.0.1:5432/postgres`; without it those tests pass unrun.

use std::time::{Duration, SystemTime};

use jwt_sessions::{
    MemoryRefreshStore, Reason, RefreshError, RefreshStore, RefreshTokens, token_hash,
};

/// 2026-01-01 12:00 UTC.
fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_268_800)
}

fn later(seconds: u64) -> SystemTime {
    t0() + Duration::from_secs(seconds)
}

fn no_grace<S: RefreshStore>(store: S) -> RefreshTokens<S> {
    RefreshTokens::new(store).with_reuse_grace(Duration::ZERO)
}

fn rejected<T: std::fmt::Debug>(result: Result<T, RefreshError>) -> Reason {
    match result {
        Err(RefreshError::Rejected(reason)) => reason,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

async fn rotation_spends_the_token_and_issues_a_successor<S: RefreshStore>(store: S) {
    let tokens = no_grace(store);
    let first = tokens.start("u1", t0()).await.unwrap();
    let rotated = tokens.rotate(&first, later(60)).await.unwrap();
    assert_eq!(rotated.user_id, "u1");
    assert_ne!(rotated.token, first);
    let again = tokens.rotate(&rotated.token, later(120)).await.unwrap();
    assert_eq!(again.family_id, rotated.family_id);
}

/// The theft case: the attacker's copy and the user's live token both die, whichever of them
/// is the thief.
async fn a_replayed_token_revokes_the_whole_family<S: RefreshStore>(store: S) {
    let tokens = no_grace(store);
    let stolen = tokens.start("u1", t0()).await.unwrap();
    let legit = tokens.rotate(&stolen, later(60)).await.unwrap(); // the real user refreshes
    assert_eq!(
        rejected(tokens.rotate(&stolen, later(120)).await),
        Reason::Reused
    ); // the thief replays
    assert_eq!(
        rejected(tokens.rotate(&legit.token, later(180)).await),
        Reason::Revoked
    );
}

async fn a_replay_within_the_grace_window_is_two_tabs_not_a_thief<S: RefreshStore>(store: S) {
    let tokens = RefreshTokens::new(store).with_reuse_grace(Duration::from_secs(10));
    let shared = tokens.start("u1", t0()).await.unwrap();
    let a = tokens.rotate(&shared, later(60)).await.unwrap();
    let b = tokens.rotate(&shared, later(65)).await.unwrap(); // the second tab, 5 s later
    assert_eq!(a.family_id, b.family_id);
    assert_ne!(a.token, b.token);
    tokens.rotate(&a.token, later(70)).await.unwrap();
    tokens.rotate(&b.token, later(70)).await.unwrap();
    // 20 s on: not a race any more.
    assert_eq!(
        rejected(tokens.rotate(&shared, later(80)).await),
        Reason::Reused
    );
}

/// `mark_used` is atomic: with no grace, of two refreshes racing on one token exactly one
/// succeeds, and the loser, a reuse, ends the family.
async fn concurrent_rotations_spend_a_token_once<S: RefreshStore>(store: S) {
    let tokens = no_grace(store);
    for round in 0..20 {
        let token = tokens.start("u1", t0()).await.unwrap();
        let (a, b) = tokio::join!(
            tokens.rotate(&token, later(1)),
            tokens.rotate(&token, later(1))
        );
        let lost = [&a, &b].iter().filter(|r| r.is_err()).count();
        assert_eq!(lost, 1, "round {round}: {a:?} {b:?}");
        let winner = a.or(b).unwrap();
        assert_eq!(
            rejected(tokens.rotate(&winner.token, later(2)).await),
            Reason::Revoked
        );
    }
}

async fn expired_unknown_and_logged_out<S: RefreshStore>(store: S) {
    let tokens = RefreshTokens::new(store).with_ttl(Duration::from_secs(3600));
    let token = tokens.start("u1", t0()).await.unwrap();
    assert_eq!(
        rejected(tokens.rotate(&token, later(3600)).await),
        Reason::Expired
    );
    assert_eq!(
        rejected(tokens.rotate(&token, later(3601)).await),
        Reason::Expired
    );
    assert_eq!(
        rejected(tokens.rotate("never-issued", t0()).await),
        Reason::Unknown
    );
    assert_eq!(rejected(tokens.rotate("", t0()).await), Reason::Unknown);

    let session = tokens.start("u1", t0()).await.unwrap();
    tokens.revoke(&session, later(1)).await.unwrap();
    assert_eq!(
        rejected(tokens.rotate(&session, later(2)).await),
        Reason::Revoked
    );
    tokens.revoke("never-issued", later(3)).await.unwrap(); // signing out twice is fine
    tokens.revoke(&session, later(3)).await.unwrap();
}

async fn revoke_user_ends_every_session_and_only_theirs<S: RefreshStore>(store: S) {
    let tokens = RefreshTokens::new(store);
    let phone = tokens.start("u1", t0()).await.unwrap();
    let laptop = tokens.start("u1", t0()).await.unwrap();
    let other = tokens.start("u2", t0()).await.unwrap();
    assert_eq!(tokens.revoke_user("u1", later(1)).await.unwrap(), 2);
    assert_eq!(
        tokens.revoke_user("u1", later(1)).await.unwrap(),
        0,
        "already revoked"
    );
    assert_eq!(tokens.revoke_user("nobody", later(1)).await.unwrap(), 0);
    for token in [&phone, &laptop] {
        assert_eq!(
            rejected(tokens.rotate(token, later(2)).await),
            Reason::Revoked
        );
    }
    tokens.rotate(&other, later(2)).await.unwrap();
}

async fn only_a_hash_is_stored_and_expired_tokens_purge<S: RefreshStore>(store: S) {
    let tokens = RefreshTokens::new(store).with_ttl(Duration::from_secs(60));
    let token = tokens.start("u1", t0()).await.unwrap();
    let store = tokens.store();
    assert_eq!(store.get(&token).await.unwrap(), None);
    let record = store
        .get(&token_hash(&token))
        .await
        .unwrap()
        .expect("stored by its hash");
    assert_eq!((record.issued_at, record.expires_at), (t0(), later(60)));
    assert_eq!((record.used_at, record.family_revoked_at), (None, None));
    assert_eq!(record.user_id, "u1");

    assert_eq!(
        tokens.purge(later(60)).await.unwrap(),
        0,
        "not expired before its last second"
    );
    assert_eq!(tokens.purge(later(61)).await.unwrap(), 1);
    assert_eq!(store.get(&token_hash(&token)).await.unwrap(), None);
    assert_eq!(
        rejected(tokens.rotate(&token, later(62)).await),
        Reason::Unknown
    );
}

async fn a_token_for_a_family_that_does_not_exist_is_a_store_error<S: RefreshStore>(store: S) {
    assert!(
        store
            .add_token("hash", "no-such-family", t0(), later(60))
            .await
            .is_err()
    );
    assert!(!store.mark_used("no-such-token", t0()).await.unwrap());
    store.revoke_family("no-such-family", t0()).await.unwrap();
}

/// Every behaviour above, against the store `$make` yields (with whatever must outlive it).
macro_rules! against {
    ($module:ident, $make:expr) => {
        mod $module {
            use super::*;

            macro_rules! case {
                ($name:ident) => {
                    #[tokio::test(flavor = "multi_thread")]
                    async fn $name() {
                        if let Some((store, _kept)) = $make.await {
                            super::$name(store).await;
                        }
                    }
                };
            }
            case!(rotation_spends_the_token_and_issues_a_successor);
            case!(a_replayed_token_revokes_the_whole_family);
            case!(a_replay_within_the_grace_window_is_two_tabs_not_a_thief);
            case!(concurrent_rotations_spend_a_token_once);
            case!(expired_unknown_and_logged_out);
            case!(revoke_user_ends_every_session_and_only_theirs);
            case!(only_a_hash_is_stored_and_expired_tokens_purge);
            case!(a_token_for_a_family_that_does_not_exist_is_a_store_error);
        }
    };
}

against!(memory, async { Some((MemoryRefreshStore::new(), ())) });

#[cfg(feature = "sqlx")]
mod sql {
    use jwt_sessions::SqlRefreshStore;
    use sqlx::any::AnyPoolOptions;

    use super::*;

    async fn sqlite() -> Option<(SqlRefreshStore, tempfile::TempDir)> {
        sqlx::any::install_default_drivers();
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("auth.db").display()
        );
        let pool = AnyPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        let store = SqlRefreshStore::new(pool, "auth_").unwrap();
        store.create_tables().await.unwrap();
        store.create_tables().await.unwrap(); // a second start finds them there
        Some((store, directory))
    }

    async fn postgres() -> Option<(SqlRefreshStore, ())> {
        let url = std::env::var("JWT_SESSIONS_TEST_POSTGRES_URL").ok()?;
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .unwrap();
        // Tables of its own for each test, so runs do not meet.
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let store =
            SqlRefreshStore::new(pool, &format!("t{unique}_{}_", std::process::id())).unwrap();
        store.create_tables().await.unwrap();
        Some((store, ()))
    }

    against!(on_sqlite, sqlite());
    against!(on_postgres, postgres());

    #[tokio::test]
    async fn a_prefix_that_is_not_an_identifier_is_refused() {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        for prefix in [
            "auth; DROP TABLE users; --",
            "Auth_",
            "1auth_",
            "a b",
            "a-b",
        ] {
            assert!(
                SqlRefreshStore::new(pool.clone(), prefix).is_err(),
                "{prefix:?} was accepted"
            );
        }
        assert!(SqlRefreshStore::new(pool.clone(), "").is_ok());
        assert!(SqlRefreshStore::new(pool, "auth_2_").is_ok());
    }

    #[tokio::test]
    async fn a_database_without_the_tables_is_a_store_error() {
        sqlx::any::install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let tokens = RefreshTokens::new(SqlRefreshStore::new(pool, "auth_").unwrap());
        assert!(tokens.start("u1", t0()).await.is_err());
        assert!(matches!(
            tokens.rotate("x", t0()).await,
            Err(RefreshError::Store(_))
        ));
    }
}
