use sqlx::SqlitePool;
use crate::Result;
use rand::Rng;

pub struct SessionsGenerator {
    pool: SqlitePool,
}

impl SessionsGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn get_user_pattern(&self) -> &'static str {
        let rand = rand::random::<f32>();
        if rand < 0.8 { "active" }
        else if rand < 0.95 { "casual" }
        else { "dormant" }
    }

    fn get_gap_days(&self, pattern: &str) -> i64 {
        match pattern {
            "active" => rand::rng().random_range(1..=3),
            "casual" => rand::rng().random_range(3..=7),
            "dormant" => rand::rng().random_range(7..=30),
            _ => 1,
        }
    }

    fn generate_additional_ip(&self) -> String {
        format!("72.{}.{}.{}", 
            rand::rng().random_range(1..=255),
            rand::rng().random_range(1..=255),
            rand::rng().random_range(1..=255))
    }

    fn random_time_of_day(&self) -> String {
        let hour = rand::rng().random_range(6..=23);
        let minute = rand::rng().random_range(0..=59);
        let second = rand::rng().random_range(0..=59);
        format!("{:02}:{:02}:{:02}", hour, minute, second)
    }

    fn random_session_duration_minutes(&self) -> i64 {
        rand::rng().random_range(30..=360)
    }

    fn get_user_ips(&self, primary_ip: String) -> Vec<String> {
        let mut ips = vec![primary_ip];
        if rand::random::<f32>() < 0.2 {
            ips.push(self.generate_additional_ip());
        }
        ips
    }

    async fn generate_user_sessions(&self, user_id: i64, username: &str, created_at: &str, user_ips: &[String]) -> Result<()> {
        let pattern = self.get_user_pattern();
        
        if let Ok(start_date) = chrono::NaiveDateTime::parse_from_str(created_at, "%Y-%m-%d %H:%M:%S") {
            let end_date = chrono::NaiveDateTime::parse_from_str("2025-09-08 00:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
            let mut current_date = start_date;

            while current_date < end_date {
                let gap_days = self.get_gap_days(pattern);
                current_date = current_date + chrono::Duration::days(gap_days);
                
                if current_date >= end_date { break; }

                let login_time = format!("{} {}", 
                    current_date.format("%Y-%m-%d"), self.random_time_of_day());

                let ip = &user_ips[rand::rng().random_range(0..user_ips.len())];

                if rand::random::<f32>() < 0.95 {
                    self.insert_successful_session(user_id, username, ip, &login_time, current_date).await?;
                } else {
                    self.insert_failed_session(user_id, username, ip, &login_time).await?;
                }
            }
        }
        Ok(())
    }

    async fn insert_successful_session(&self, user_id: i64, username: &str, ip: &str, login_time: &str, current_date: chrono::NaiveDateTime) -> Result<()> {
        let duration = self.random_session_duration_minutes();
        let logout_time = (current_date + chrono::Duration::minutes(duration))
            .format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query("INSERT INTO sessions (user_id, username, ip_address, login_time, logout_time, success, geo_location) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(user_id)
            .bind(username)
            .bind(ip)
            .bind(login_time)
            .bind(&logout_time)
            .bind(true)
            .bind("US East Coast")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn insert_failed_session(&self, user_id: i64, username: &str, ip: &str, login_time: &str) -> Result<()> {
        sqlx::query("INSERT INTO sessions (user_id, username, ip_address, login_time, logout_time, success, geo_location) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(user_id)
            .bind(username)
            .bind(ip)
            .bind(login_time)
            .bind(None::<String>)
            .bind(false)
            .bind("US East Coast")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn generate(&self) -> Result<()> {
        let users: Vec<(i64, String, String, String)> = sqlx::query_as(
            "SELECT id, username, created_at, last_ip_address FROM users"
        )
        .fetch_all(&self.pool)
        .await?;

        for (user_id, username, created_at, primary_ip) in users {
            let user_ips = self.get_user_ips(primary_ip);
            self.generate_user_sessions(user_id, &username, &created_at, &user_ips).await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} sessions", count.0);
        Ok(())
    }
}