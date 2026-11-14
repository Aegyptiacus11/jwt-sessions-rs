//! Password hashing: argon2id through `password-auth`, and a login check that takes the same
//! time whether or not the account exists.
//!
//! Answering an unknown login without hashing anything makes "no such account" come back
//! measurably faster than "wrong password", which tells anyone timing the endpoint which
//! logins have accounts. [`check_password`] always runs one argon2 verification.

use std::sync::LazyLock;

use password_auth::{VerifyError, generate_hash, is_hash_obsolete, verify_password};

use crate::random;

/// Verified against when there is no account, so both paths cost one argon2 verification. It
/// matches no password anyone sends: it is the hash of a random value that is not kept.
static DUMMY_HASH: LazyLock<String> = LazyLock::new(|| generate_hash(random::token()));

/// A stored value that is not a password hash this library reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the stored password hash is malformed: {0}")]
pub struct MalformedHash(pub String);

/// The argon2id hash of `password`, in PHC string format, with a salt of its own.
pub fn hash_password(password: &str) -> String {
    generate_hash(password)
}

/// Whether `password` matches `hashed`. `hashed` is `None` when there is no such account,
/// and the answer is then `false` after the same work.
pub fn check_password(password: &str, hashed: Option<&str>) -> Result<bool, MalformedHash> {
    match verify(password, hashed.unwrap_or(&DUMMY_HASH)) {
        Ok(()) => Ok(hashed.is_some()),
        Err(VerifyError::PasswordInvalid) => Ok(false),
        Err(VerifyError::Parse(e)) => Err(MalformedHash(e.to_string())),
    }
}

/// True when `hashed` was made with weaker parameters than today's defaults: hash the
/// password again on the next successful login.
pub fn needs_rehash(hashed: &str) -> Result<bool, MalformedHash> {
    is_hash_obsolete(hashed).map_err(|e| MalformedHash(e.to_string()))
}

fn verify(password: &str, hash: &str) -> Result<(), VerifyError> {
    #[cfg(test)]
    tests::VERIFIED.with_borrow_mut(|seen| seen.push(hash.to_owned()));
    verify_password(password, hash)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    thread_local! {
        /// Every hash this thread verified against.
        pub(super) static VERIFIED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    #[test]
    fn right_and_wrong_passwords() {
        let hashed = hash_password("correct horse");
        assert!(hashed.starts_with("$argon2id$"));
        assert_eq!(check_password("correct horse", Some(&hashed)), Ok(true));
        assert_eq!(check_password("wrong", Some(&hashed)), Ok(false));
        assert_ne!(
            hashed,
            hash_password("correct horse"),
            "each hash has its own salt"
        );
    }

    /// An unknown login must not answer faster than a wrong password: both run exactly one
    /// argon2 verification.
    #[test]
    fn no_account_costs_one_verification_too() {
        let other = hash_password("other");
        VERIFIED.with_borrow_mut(Vec::clear);
        assert_eq!(check_password("anything", None), Ok(false));
        assert_eq!(check_password("anything", Some(&other)), Ok(false));
        let seen = VERIFIED.with_borrow(Clone::clone);
        assert_eq!(seen, [DUMMY_HASH.clone(), other]);
    }

    #[test]
    fn a_malformed_hash_is_an_error_not_a_wrong_password() {
        assert!(check_password("x", Some("not-a-hash")).is_err());
        assert!(needs_rehash("not-a-hash").is_err());
        assert_eq!(needs_rehash(&hash_password("x")), Ok(false));
    }
}
