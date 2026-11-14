//! An in-memory [`RefreshStore`], for tests and single-process demos. A restart signs
//! everyone out.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use crate::refresh::{RefreshRecord, RefreshStore, StoreError};

#[derive(Debug)]
struct Family {
    user_id: String,
    revoked_at: Option<SystemTime>,
}

#[derive(Debug, Default)]
struct State {
    families: HashMap<String, Family>,
    tokens: HashMap<String, RefreshRecord>,
}

#[derive(Debug, Default)]
pub struct MemoryRefreshStore {
    state: Mutex<State>,
}

impl MemoryRefreshStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> Result<MutexGuard<'_, State>, StoreError> {
        // Poisoned: another thread panicked while changing the maps, which may be half done.
        self.state
            .lock()
            .map_err(|_| StoreError::new("the in-memory refresh store is poisoned"))
    }
}

impl RefreshStore for MemoryRefreshStore {
    async fn create_family(
        &self,
        family_id: &str,
        user_id: &str,
        _at: SystemTime,
    ) -> Result<(), StoreError> {
        let family = Family {
            user_id: user_id.to_owned(),
            revoked_at: None,
        };
        self.state()?.families.insert(family_id.to_owned(), family);
        Ok(())
    }

    async fn add_token(
        &self,
        token_hash: &str,
        family_id: &str,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> Result<(), StoreError> {
        let mut state = self.state()?;
        let Some(family) = state.families.get(family_id) else {
            return Err(StoreError::new(format!("no refresh family {family_id}")));
        };
        let record = RefreshRecord {
            token_hash: token_hash.to_owned(),
            family_id: family_id.to_owned(),
            user_id: family.user_id.clone(),
            issued_at,
            expires_at,
            used_at: None,
            family_revoked_at: None,
        };
        state.tokens.insert(token_hash.to_owned(), record);
        Ok(())
    }

    async fn get(&self, token_hash: &str) -> Result<Option<RefreshRecord>, StoreError> {
        let state = self.state()?;
        Ok(state.tokens.get(token_hash).map(|record| RefreshRecord {
            family_revoked_at: state
                .families
                .get(&record.family_id)
                .and_then(|f| f.revoked_at),
            ..record.clone()
        }))
    }

    async fn mark_used(&self, token_hash: &str, at: SystemTime) -> Result<bool, StoreError> {
        // One lock around the check and the change: that is what makes it atomic.
        match self.state()?.tokens.get_mut(token_hash) {
            Some(record) if record.used_at.is_none() => {
                record.used_at = Some(at);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn revoke_family(&self, family_id: &str, at: SystemTime) -> Result<(), StoreError> {
        if let Some(family) = self.state()?.families.get_mut(family_id) {
            family.revoked_at.get_or_insert(at);
        }
        Ok(())
    }

    async fn revoke_user(&self, user_id: &str, at: SystemTime) -> Result<u64, StoreError> {
        let mut revoked = 0;
        for family in self.state()?.families.values_mut() {
            if family.user_id == user_id && family.revoked_at.is_none() {
                family.revoked_at = Some(at);
                revoked += 1;
            }
        }
        Ok(revoked)
    }

    async fn purge(&self, before: SystemTime) -> Result<u64, StoreError> {
        let mut state = self.state()?;
        let total = state.tokens.len();
        state.tokens.retain(|_, record| record.expires_at >= before);
        Ok((total - state.tokens.len()) as u64)
    }
}
