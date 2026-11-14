//! A [`RefreshStore`] on SQLite or Postgres, through sqlx's `Any` driver.
//!
//! Two tables, `<prefix>refresh_families` and `<prefix>refresh_tokens`; times are
//! milliseconds since the Unix epoch in `BIGINT` columns, which both databases read alike.
//! [`SqlRefreshStore::create_tables`] makes them, and [`SqlRefreshStore::schema`] gives the
//! statements to an application that keeps its own migrations.
//!
//! `mark_used` is a conditional `UPDATE ... WHERE used_at IS NULL`, which is what makes it
//! atomic: of two concurrent refreshes with the same token, exactly one changes a row.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::{AnyPool, AssertSqlSafe, Row};

use crate::refresh::{RefreshRecord, RefreshStore, StoreError};

#[derive(Debug, Clone)]
pub struct SqlRefreshStore {
    pool: AnyPool,
    families: String,
    tokens: String,
}

impl SqlRefreshStore {
    /// A store on `pool` with tables named `<prefix>refresh_families` and
    /// `<prefix>refresh_tokens`. The prefix goes into the SQL as it is, so it may only hold
    /// lower-case letters, digits and underscores; `auth_` is the usual one.
    ///
    /// The pool is the application's: call `sqlx::any::install_default_drivers()` before
    /// connecting it.
    pub fn new(pool: AnyPool, prefix: &str) -> Result<Self, StoreError> {
        let safe = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        if !prefix.chars().all(safe) || prefix.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(StoreError::new(format!(
                "table prefix {prefix:?}: only lower-case letters, digits and underscores, not starting with a digit"
            )));
        }
        Ok(Self {
            pool,
            families: format!("{prefix}refresh_families"),
            tokens: format!("{prefix}refresh_tokens"),
        })
    }

    /// The statements that create the tables and their indexes, for SQLite and Postgres.
    pub fn schema(&self) -> Vec<String> {
        let (families, tokens) = (&self.families, &self.tokens);
        vec![
            format!(
                "CREATE TABLE IF NOT EXISTS {families} (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at BIGINT NOT NULL,
                    revoked_at BIGINT
                )"
            ),
            format!(
                "CREATE TABLE IF NOT EXISTS {tokens} (
                    token_hash TEXT PRIMARY KEY,
                    family_id TEXT NOT NULL REFERENCES {families} (id) ON DELETE CASCADE,
                    issued_at BIGINT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    used_at BIGINT
                )"
            ),
            format!("CREATE INDEX IF NOT EXISTS ix_{families}_user_id ON {families} (user_id)"),
            format!("CREATE INDEX IF NOT EXISTS ix_{tokens}_family_id ON {tokens} (family_id)"),
            format!("CREATE INDEX IF NOT EXISTS ix_{tokens}_expires_at ON {tokens} (expires_at)"),
        ]
    }

    /// Create the tables and indexes if they are not there.
    pub async fn create_tables(&self) -> Result<(), StoreError> {
        for statement in self.schema() {
            sqlx::query(AssertSqlSafe(statement))
                .execute(&self.pool)
                .await
                .map_err(StoreError::new)?;
        }
        Ok(())
    }
}

/// Milliseconds since the Unix epoch.
fn millis(at: SystemTime) -> Result<i64, StoreError> {
    let since = at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::new("a time before 1970 cannot be stored"))?;
    i64::try_from(since.as_millis()).map_err(|_| StoreError::new("a time too far ahead to store"))
}

fn time(millis: i64) -> Result<SystemTime, StoreError> {
    let millis = u64::try_from(millis)
        .map_err(|_| StoreError::new(format!("a stored time is negative: {millis}")))?;
    Ok(UNIX_EPOCH + Duration::from_millis(millis))
}

impl RefreshStore for SqlRefreshStore {
    async fn create_family(
        &self,
        family_id: &str,
        user_id: &str,
        at: SystemTime,
    ) -> Result<(), StoreError> {
        let sql = format!(
            "INSERT INTO {} (id, user_id, created_at) VALUES ($1, $2, $3)",
            self.families
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(family_id)
            .bind(user_id)
            .bind(millis(at)?)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(())
    }

    async fn add_token(
        &self,
        token_hash: &str,
        family_id: &str,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> Result<(), StoreError> {
        let sql = format!(
            "INSERT INTO {} (token_hash, family_id, issued_at, expires_at) VALUES ($1, $2, $3, $4)",
            self.tokens
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(token_hash)
            .bind(family_id)
            .bind(millis(issued_at)?)
            .bind(millis(expires_at)?)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(())
    }

    async fn get(&self, token_hash: &str) -> Result<Option<RefreshRecord>, StoreError> {
        let sql = format!(
            "SELECT t.family_id, f.user_id, t.issued_at, t.expires_at, t.used_at, f.revoked_at
             FROM {} t JOIN {} f ON f.id = t.family_id WHERE t.token_hash = $1",
            self.tokens, self.families
        );
        let row = sqlx::query(AssertSqlSafe(sql))
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::new)?;
        let Some(row) = row else { return Ok(None) };
        let optional = |column: &str| -> Result<Option<SystemTime>, StoreError> {
            row.try_get::<Option<i64>, _>(column)
                .map_err(StoreError::new)?
                .map(time)
                .transpose()
        };
        Ok(Some(RefreshRecord {
            token_hash: token_hash.to_owned(),
            family_id: row.try_get("family_id").map_err(StoreError::new)?,
            user_id: row.try_get("user_id").map_err(StoreError::new)?,
            issued_at: time(row.try_get("issued_at").map_err(StoreError::new)?)?,
            expires_at: time(row.try_get("expires_at").map_err(StoreError::new)?)?,
            used_at: optional("used_at")?,
            family_revoked_at: optional("revoked_at")?,
        }))
    }

    async fn mark_used(&self, token_hash: &str, at: SystemTime) -> Result<bool, StoreError> {
        let sql = format!(
            "UPDATE {} SET used_at = $1 WHERE token_hash = $2 AND used_at IS NULL",
            self.tokens
        );
        let done = sqlx::query(AssertSqlSafe(sql))
            .bind(millis(at)?)
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(done.rows_affected() == 1)
    }

    async fn revoke_family(&self, family_id: &str, at: SystemTime) -> Result<(), StoreError> {
        let sql = format!(
            "UPDATE {} SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL",
            self.families
        );
        sqlx::query(AssertSqlSafe(sql))
            .bind(millis(at)?)
            .bind(family_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(())
    }

    async fn revoke_user(&self, user_id: &str, at: SystemTime) -> Result<u64, StoreError> {
        let sql = format!(
            "UPDATE {} SET revoked_at = $1 WHERE user_id = $2 AND revoked_at IS NULL",
            self.families
        );
        let done = sqlx::query(AssertSqlSafe(sql))
            .bind(millis(at)?)
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(done.rows_affected())
    }

    async fn purge(&self, before: SystemTime) -> Result<u64, StoreError> {
        let sql = format!("DELETE FROM {} WHERE expires_at < $1", self.tokens);
        let done = sqlx::query(AssertSqlSafe(sql))
            .bind(millis(before)?)
            .execute(&self.pool)
            .await
            .map_err(StoreError::new)?;
        Ok(done.rows_affected())
    }
}
