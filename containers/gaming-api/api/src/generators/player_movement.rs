use sqlx::SqlitePool;
use crate::Result;
use rand::Rng;

pub struct PlayerMovementGenerator {
    pool: SqlitePool,
}

impl PlayerMovementGenerator {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn get_weighted_location(&self) -> i64 {
        let rand = rand::random::<f32>();
        if rand < 0.7 { 3 }      // Game
        else if rand < 0.85 { 4 } // Marketplace  
        else if rand < 0.95 { 5 } // Chat
        else { 5 }               // Settings
    }

    fn get_stay_duration_minutes(&self, location_id: i64) -> i64 {
        match location_id {
            1 => rand::rng().random_range(1..=5),    // Lobby: very brief
            3 => rand::rng().random_range(10..=60),  // Game: longest stays
            4 => rand::rng().random_range(5..=20),   // Marketplace: moderate
            5 => rand::rng().random_range(2..=15),   // Chat: moderate
            6 => rand::rng().random_range(1..=10),   // Settings: brief
            _ => 5,
        }
    }

    async fn generate_session_movements(&self, session_id: i64, user_id: i64, login_time: &str, logout_time: &str) -> Result<()> {
        if let (Ok(login_dt), Ok(logout_dt)) = (
            chrono::NaiveDateTime::parse_from_str(login_time, "%Y-%m-%d %H:%M:%S"),
            chrono::NaiveDateTime::parse_from_str(logout_time, "%Y-%m-%d %H:%M:%S")
        ) {
            let session_duration = (logout_dt - login_dt).num_minutes();
            
            // Always start in Lobby
            sqlx::query("INSERT INTO player_movement (user_id, session_id, location_id, timestamp) VALUES (?, ?, ?, ?)")
                .bind(user_id)
                .bind(session_id)
                .bind(1) // Lobby
                .bind(login_time)
                .execute(&self.pool)
                .await?;

            let mut current_time = login_dt + chrono::Duration::minutes(rand::rng().random_range(1..=3));
            
            if session_duration < 60 {
                // Short session: just go to Game
                sqlx::query("INSERT INTO player_movement (user_id, session_id, location_id, timestamp) VALUES (?, ?, ?, ?)")
                    .bind(user_id)
                    .bind(session_id)
                    .bind(3) // Game
                    .bind(current_time.format("%Y-%m-%d %H:%M:%S").to_string())
                    .execute(&self.pool)
                    .await?;
            } else {
                // Longer session: generate multiple movements
                while current_time < logout_dt - chrono::Duration::minutes(5) {
                    let next_location = self.get_weighted_location();
                    let stay_duration = self.get_stay_duration_minutes(next_location);
                    
                    sqlx::query("INSERT INTO player_movement (user_id, session_id, location_id, timestamp) VALUES (?, ?, ?, ?)")
                        .bind(user_id)
                        .bind(session_id)
                        .bind(next_location)
                        .bind(current_time.format("%Y-%m-%d %H:%M:%S").to_string())
                        .execute(&self.pool)
                        .await?;
                    
                    current_time = current_time + chrono::Duration::minutes(stay_duration);
                }
            }
        }
        Ok(())
    }

    pub async fn generate(&self) -> Result<()> {
        // Get all successful sessions
        let sessions: Vec<(i64, i64, String, String, String)> = sqlx::query_as(
            "SELECT id, user_id, username, login_time, logout_time FROM sessions WHERE success = 1 AND logout_time IS NOT NULL"
        )
        .fetch_all(&self.pool)
        .await?;

        for (session_id, user_id, _username, login_time, logout_time) in sessions {
            self.generate_session_movements(session_id, user_id, &login_time, &logout_time).await?;
        }

        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM player_movement")
            .fetch_one(&self.pool)
            .await?;

        println!("Generated {} player movements", count.0);
        Ok(())
    }
}