use sqlx::SqlitePool;
use crate::Result;
use super::static_data::StaticUser;
use rand::Rng;
use std::fs;

pub struct UserGenerator {
    pool: SqlitePool,
}

impl UserGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn load_passwords() -> Result<Vec<String>> {
        let bytes = fs::read("./data/rockyou.txt")?;
        let passwords_text = String::from_utf8_lossy(&bytes);
        Ok(passwords_text
            .lines()
            .take(10000) // Only use first 10k passwords for performance
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect())
    }

    fn generate_account_status_id(&self) -> i64 {
        let rand = rand::random::<f32>();
        if rand < 0.8 { 1 }      // active
        else if rand < 0.9 { 2 } // inactive
        else if rand < 0.95 { 4 } // flagged  
        else if rand < 0.98 { 3 } // suspended
        else { 5 }               // banned
    }

    fn generate_password_last_changed(&self, created_at: &str) -> Option<String> {
        if rand::random::<f32>() < 0.5 {
            return Some(created_at.to_string()); // 50% chance no password change
        }
        
        if let Ok(created) = chrono::NaiveDateTime::parse_from_str(created_at, "%Y-%m-%d %H:%M:%S") {
            let now = chrono::NaiveDateTime::parse_from_str("2025-09-08 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
            let midpoint = created + (now - created) / 2;
            
            let random_time = created + chrono::Duration::seconds(
                rand::rng().random_range(0..=(midpoint - created).num_seconds())
            );
            
            Some(random_time.format("%Y-%m-%d %H:%M:%S").to_string())
        } else {
            Some(created_at.to_string())
        }
    }

    pub async fn generate(&self, data: &[StaticUser]) -> Result<()> {
        let passwords = Self::load_passwords()?;
        
        for user in data {
            let account_status_id = self.generate_account_status_id();
            let password = &passwords[rand::rng().random_range(0..passwords.len())];
            let password_last_changed = self.generate_password_last_changed(&user.created_at);
            
            sqlx::query("INSERT INTO users (username, password_text, email, created_at, account_status_id, email_last_changed, password_last_changed, first_name, last_name, last_ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(&user.username)
                .bind(password)
                .bind(&user.email)
                .bind(&user.created_at)
                .bind(account_status_id)
                .bind(&user.created_at) // email_last_changed = created_at
                .bind(password_last_changed)
                .bind(&user.first_name)
                .bind(&user.last_name)
                .bind(&user.last_ip_address)
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
