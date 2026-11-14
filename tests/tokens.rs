use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jwt_sessions::{AccessTokens, ConfigError, IssueError};
use serde_json::{Map, Value, json};

const SECRET: &str = "test-secret-that-is-comfortably-over-32-bytes";

fn claims(value: Value) -> Map<String, Value> {
    value.as_object().expect("an object").clone()
}

fn none() -> Map<String, Value> {
    Map::new()
}

/// A JWT signed by hand, to send what `AccessTokens` would never issue.
fn signed(header: Value, payload: Value, secret: &str) -> String {
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    let algorithm = match header["alg"].as_str() {
        Some("HS256") => Algorithm::HS256,
        Some("HS384") => Algorithm::HS384,
        other => panic!("unexpected alg {other:?}"),
    };
    jsonwebtoken::encode(
        &Header::new(algorithm),
        &payload,
        &EncodingKey::from_secret(secret.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn round_trip_carries_the_claims() {
    let tokens = AccessTokens::new(SECRET).unwrap();
    let verified = tokens
        .verify(
            &tokens
                .issue("user-1", &claims(json!({"role": "admin"})))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(verified.sub(), "user-1");
    assert_eq!(verified.get("role"), Some(&json!("admin")));
    assert_eq!(verified.get("typ"), Some(&json!("access")));
    let lifetime = verified.get("exp").unwrap().as_u64().unwrap()
        - verified.get("iat").unwrap().as_u64().unwrap();
    assert_eq!(lifetime, 15 * 60);
    assert_eq!(verified.get("jti").unwrap().as_str().unwrap().len(), 32);
}

#[test]
fn expired_forged_and_foreign_tokens_are_refused() {
    let tokens = AccessTokens::new(SECRET)
        .unwrap()
        .with_ttl(Duration::from_secs(60))
        .unwrap();
    let old = tokens
        .issue_at("u", &none(), SystemTime::now() - Duration::from_secs(300))
        .unwrap();
    assert!(tokens.verify(&old).is_err(), "expired");

    let other = AccessTokens::new("another-secret-also-long-enough-for-hs256").unwrap();
    assert!(
        tokens.verify(&other.issue("u", &none()).unwrap()).is_err(),
        "another secret"
    );

    let good = tokens.issue("u", &none()).unwrap();
    let mut tampered = good.clone();
    tampered.pop();
    tampered.push(if good.ends_with('A') { 'B' } else { 'A' });
    assert!(tokens.verify(&tampered).is_err(), "a changed signature");
    assert!(tokens.verify("not-a-jwt").is_err());
    assert!(tokens.verify("").is_err());

    // Not an access token: right key, wrong type.
    let payload = json!({"sub": "u", "typ": "refresh", "iat": now_secs(), "exp": now_secs() + 300});
    let refresh_like = signed(json!({"alg": "HS256"}), payload, SECRET);
    assert_eq!(
        tokens.verify(&refresh_like).unwrap_err().0,
        "not an access token"
    );
}

#[test]
fn missing_claims_are_refused() {
    let tokens = AccessTokens::new(SECRET).unwrap();
    let full = json!({"sub": "u", "typ": "access", "iat": now_secs(), "exp": now_secs() + 300});
    assert!(
        tokens
            .verify(&signed(json!({"alg": "HS256"}), full.clone(), SECRET))
            .is_ok()
    );
    for missing in ["sub", "typ", "iat", "exp"] {
        let mut payload = full.clone();
        payload.as_object_mut().unwrap().remove(missing);
        let token = signed(json!({"alg": "HS256"}), payload, SECRET);
        assert!(
            tokens.verify(&token).is_err(),
            "a token without {missing} was accepted"
        );
    }
    let numeric_sub =
        json!({"sub": 7, "typ": "access", "iat": now_secs(), "exp": now_secs() + 300});
    assert!(
        tokens
            .verify(&signed(json!({"alg": "HS256"}), numeric_sub, SECRET))
            .is_err()
    );
}

#[test]
fn the_algorithm_is_never_taken_from_the_token() {
    let tokens = AccessTokens::new(SECRET).unwrap();
    let payload = json!({"sub": "u", "typ": "access", "iat": now_secs(), "exp": now_secs() + 300});

    // "alg": "none", no signature.
    let part = |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).unwrap());
    let unsigned = format!(
        "{}.{}.",
        part(&json!({"alg": "none", "typ": "JWT"})),
        part(&payload)
    );
    assert!(tokens.verify(&unsigned).is_err());

    // Correctly signed with the same secret, but with another HMAC.
    let hs384 = signed(json!({"alg": "HS384"}), payload, SECRET);
    assert!(tokens.verify(&hs384).is_err());
}

#[test]
fn a_short_secret_a_zero_ttl_and_reserved_claims_are_refused() {
    assert_eq!(
        AccessTokens::new("short").unwrap_err(),
        ConfigError::ShortSecret
    );
    assert_eq!(
        AccessTokens::new(&"x".repeat(31)).unwrap_err(),
        ConfigError::ShortSecret
    );
    assert!(AccessTokens::new(&"x".repeat(32)).is_ok());
    assert_eq!(
        AccessTokens::new(SECRET)
            .unwrap()
            .with_ttl(Duration::from_millis(900))
            .unwrap_err(),
        ConfigError::ZeroTtl
    );
    let tokens = AccessTokens::new(SECRET).unwrap();
    assert_eq!(
        tokens
            .issue(
                "u",
                &claims(json!({"sub": "someone-else", "exp": 1, "role": "x"}))
            )
            .unwrap_err(),
        IssueError::ReservedClaims(vec!["exp".into(), "sub".into()])
    );
}

#[test]
fn issuer_and_audience_are_checked_when_set() {
    let tokens = AccessTokens::new(SECRET)
        .unwrap()
        .with_issuer("https://a.example")
        .with_audience("api");
    assert_eq!(
        tokens
            .verify(&tokens.issue("u", &none()).unwrap())
            .unwrap()
            .get("aud"),
        Some(&json!("api"))
    );

    let elsewhere = AccessTokens::new(SECRET)
        .unwrap()
        .with_issuer("https://b.example")
        .with_audience("api");
    assert!(
        tokens
            .verify(&elsewhere.issue("u", &none()).unwrap())
            .is_err(),
        "another issuer"
    );
    let other_audience = AccessTokens::new(SECRET)
        .unwrap()
        .with_issuer("https://a.example")
        .with_audience("web");
    assert!(
        tokens
            .verify(&other_audience.issue("u", &none()).unwrap())
            .is_err(),
        "another audience"
    );
    let plain = AccessTokens::new(SECRET).unwrap();
    assert!(
        tokens.verify(&plain.issue("u", &none()).unwrap()).is_err(),
        "no issuer or audience"
    );
    // A token made for an audience is not for a verifier that names none.
    assert!(plain.verify(&tokens.issue("u", &none()).unwrap()).is_err());
}

#[test]
fn leeway_tolerates_a_slow_clock() {
    let strict = AccessTokens::new(SECRET)
        .unwrap()
        .with_ttl(Duration::from_secs(60))
        .unwrap();
    let just_expired = strict
        .issue_at("u", &none(), SystemTime::now() - Duration::from_secs(70))
        .unwrap();
    assert!(strict.verify(&just_expired).is_err());
    assert!(
        strict
            .clone()
            .with_leeway(Duration::from_secs(30))
            .verify(&just_expired)
            .is_ok()
    );
}

#[test]
fn debug_does_not_print_the_secret() {
    let shown = format!("{:?}", AccessTokens::new(SECRET).unwrap());
    assert!(!shown.contains(SECRET), "{shown}");
}
