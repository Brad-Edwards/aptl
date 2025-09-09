use sqlx::SqlitePool;
use crate::Result;
use super::static_data::StaticAccountStatus;

pub struct AccountStatusGenerator {
    pool: SqlitePool,
}

impl AccountStatusGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn generate(&self, data: &[StaticAccountStatus]) -> Result<()> {
        // Insert account statuses
        for status in data {
            sqlx::query!(
                "INSERT INTO account_status (status, description) VALUES (?, ?)",
                status.status,
                status.description
            )
            .execute(&self.pool)
            .await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM account_status")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} account statuses", count.0);
        Ok(())
    }
}