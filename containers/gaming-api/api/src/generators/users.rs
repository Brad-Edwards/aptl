use serde::Deserialize;
use sqlx::SqlitePool;
use std::fs;
use crate::Result;

#[derive(Debug, Deserialize)]
struct StaticUser {
    username: String,
    email: String,
    password_hash: String,
    created_at: String,
    account_value: i64,
}

#[derive(Debug, Deserialize)]
struct StaticData {
    users: Vec<StaticUser>,
}

pub struct UsersGenerator {
    pool: SqlitePool,
}

impl UsersGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn generate(&self) -> Result<()> {
        // Load static data
        let data = fs::read_to_string("./data/static-data.json")?;
        let static_data: StaticData = serde_json::from_str(&data)?;

        // Clear existing users
        sqlx::query("DELETE FROM users").execute(&self.pool).await?;

        // Insert users
        for user in static_data.users {
            sqlx::query!(
                "INSERT INTO users (username, password, email, created_at, account_value, account_status_id) 
                 VALUES (?, ?, ?, ?, ?, ?)",
                user.username,
                user.password_hash, // Store as plaintext password
                user.email,
                user.created_at,
                user.account_value,
                1 // Default to 'active' status
            )
            .execute(&self.pool)
            .await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} users", count.0);
        Ok(())
    }
}